/*
 * Copyright 2022 Post CH Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ch.post.it.evoting.cryptoprimitives.internal.mixnet;

import static ch.post.it.evoting.cryptoprimitives.internal.elgamal.ElGamalMultiRecipientCiphertexts.getCiphertext;
import static ch.post.it.evoting.cryptoprimitives.internal.elgamal.ElGamalMultiRecipientCiphertexts.getCiphertextVectorExponentiation;
import static ch.post.it.evoting.cryptoprimitives.internal.elgamal.ElGamalMultiRecipientMessages.constantMessage;
import static ch.post.it.evoting.cryptoprimitives.math.GroupVector.toGroupVector;
import static ch.post.it.evoting.cryptoprimitives.internal.mixnet.CommitmentService.getCommitment;
import static ch.post.it.evoting.cryptoprimitives.internal.mixnet.CommitmentService.getCommitmentMatrix;
import static ch.post.it.evoting.cryptoprimitives.internal.utils.ConversionsInternal.byteArrayToInteger;
import static ch.post.it.evoting.cryptoprimitives.internal.utils.Verifiable.create;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.MoreCollectors.onlyElement;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.IntFunction;
import java.util.stream.IntStream;
import java.util.stream.LongStream;
import java.util.stream.Stream;

import com.google.common.annotations.VisibleForTesting;

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.internal.elgamal.ElGamalMultiRecipientMessages;
import ch.post.it.evoting.cryptoprimitives.internal.elgamal.ElGamalMultiRecipientCiphertexts;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientMessage;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.internal.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableBigInteger;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupMatrix;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.internal.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.internal.utils.Verifiable;
import ch.post.it.evoting.cryptoprimitives.mixnet.MultiExponentiationArgument;
import ch.post.it.evoting.cryptoprimitives.mixnet.MultiExponentiationStatement;
import ch.post.it.evoting.cryptoprimitives.mixnet.MultiExponentiationWitness;
import ch.post.it.evoting.cryptoprimitives.utils.VerificationResult;

/**
 * Service to generate multi exponentiation arguments.
 *
 * <p>This class is thread safe.</p>
 */
@SuppressWarnings("java:S117")
final class MultiExponentiationArgumentService {

	private final ElGamalMultiRecipientPublicKey pk;
	private final CommitmentKey ck;
	private final RandomService randomService;
	private final HashService hashService;
	private final GqGroup gqGroup;
	private final ZqGroup zqGroup;

	/**
	 * Instantiates a new multi exponentiation argument service.
	 * <p>
	 * The parameters must abide by the following conditions:
	 * <ul>
	 *     <li>be non null</li>
	 *     <li>the public key and commitment key must be from the same group</li>
	 *     <li>the public key and commitment key must be of the same size</li>
	 * </ul>
	 *
	 * @param publicKey     the public key with which to encrypt ciphertexts
	 * @param commitmentKey the key used for commitments
	 * @param randomService the service providing randomness
	 * @param hashService   the service providing hashing
	 */
	MultiExponentiationArgumentService(final ElGamalMultiRecipientPublicKey publicKey, final CommitmentKey commitmentKey,
			final RandomService randomService, final HashService hashService) {

		// Null checking.
		checkNotNull(publicKey);
		checkNotNull(commitmentKey);
		checkNotNull(randomService);
		checkNotNull(hashService);

		// Group checking.
		checkArgument(publicKey.getGroup().equals(commitmentKey.getGroup()), "The public key and commitment key must belong to the same group");

		// Check hash length
		final BigInteger q = publicKey.getGroup().getQ();
		checkArgument(hashService.getHashLength() * Byte.SIZE < q.bitLength(),
				"The hash service's bit length must be smaller than the bit length of q.");

		this.pk = publicKey;
		this.ck = commitmentKey;
		this.gqGroup = publicKey.getGroup();
		this.zqGroup = ZqGroup.sameOrderAs(gqGroup);
		this.randomService = randomService;
		this.hashService = hashService;
	}

	/**
	 * Generates a multi exponentiation proof using the statement and witness.
	 * <p>
	 * The statement and the witness must abide by the following conditions:
	 * <ul>
	 *     <li>be non null</li>
	 *     <li>the statement dimension m and n must be equal to the witness dimensions m and n</li>
	 *     <li>n must be smaller than the size of the public key</li>
	 * </ul>
	 *
	 * @param statement the statement, which must belong to the same Gq group as the public key and commitment key
	 * @param witness   the witness, which must belong to a Zq group of the same order as the public key and commitment key
	 */
	MultiExponentiationArgument getMultiExponentiationArgument(final MultiExponentiationStatement statement,
			final MultiExponentiationWitness witness) {

		//Null checking
		checkNotNull(statement);
		checkNotNull(witness);

		final GroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> C_matrix = statement.get_C_matrix();
		final ElGamalMultiRecipientCiphertext C = statement.get_C();
		final GroupVector<GqElement, GqGroup> c_A = statement.get_c_A();
		final GroupMatrix<ZqElement, ZqGroup> A = witness.get_A();
		final GroupVector<ZqElement, ZqGroup> r_vector = witness.get_r();
		final ZqElement rho = witness.get_rho();
		final int m = statement.get_m();
		final int n = statement.get_n();
		final int l = C_matrix.getElementSize();
		final int k_size = pk.size();
		final int nu = ck.size();
		final BigInteger q = this.gqGroup.getQ();

		//Dimension checking
		checkArgument(statement.get_n() == witness.get_n(), "Statement and witness do not have compatible n dimension.");
		checkArgument(statement.get_m() == witness.get_m(), "Statement and witness do not have compatible m dimension.");
		checkArgument(witness.get_m() > 0, "The dimension m must be strictly positive.");
		checkArgument(witness.get_n() > 0, "The dimension n must be strictly positive.");
		checkArgument(witness.get_n() <= nu, "The number of rows of matrix A must be smaller or equal to the size of the commitment key.");

		//Group checking
		checkArgument(this.gqGroup.equals(statement.getGroup()), "The statement must belong to the same group as the public key and commitment key.");
		checkArgument(this.gqGroup.hasSameOrderAs(witness.getGroup()), "The witness must belong to a ZqGroup of order q.");

		checkArgument(0 < l, "The ciphertexts must have at least 1 element.");
		checkArgument(l <= k_size, "The ciphertexts must be smaller than the public key.");

		//Ensure that C is the result of the re-encryption and multi exponentiation of matrix C with exponents matrix A
		final ElGamalMultiRecipientCiphertext computedCCiphertext = multiExponentiation(C_matrix, A, rho, m, l);
		checkArgument(C.equals(computedCCiphertext),
				"The computed multi exponentiation ciphertext does not correspond to the one provided in the statement.");

		//Ensure that cA is the commitment to matrix A
		checkArgument(c_A.equals(getCommitmentMatrix(A, r_vector, ck)), "The commitment provided does not correspond to the matrix A.");

		//Algorithm
		//Generate a_0, r_0, b, s, tau,
		final GroupVector<ZqElement, ZqGroup> a_0 = randomService.genRandomVector(q, n);
		final ZqElement r_0 = ZqElement.create(randomService.genRandomInteger(q), zqGroup);
		final List<ZqElement> b_mutable = new ArrayList<>(randomService.genRandomVector(q, 2 * m));
		final List<ZqElement> s_mutable = new ArrayList<>(randomService.genRandomVector(q, 2 * m));
		final List<ZqElement> tau_mutable = new ArrayList<>(randomService.genRandomVector(q, 2 * m));
		final ZqElement zero = ZqElement.create(0, zqGroup);
		b_mutable.set(m, zero);
		s_mutable.set(m, zero);
		tau_mutable.set(m, rho);
		final GroupVector<ZqElement, ZqGroup> b_vector = GroupVector.from(b_mutable);
		final GroupVector<ZqElement, ZqGroup> s_vector = GroupVector.from(s_mutable);
		final GroupVector<ZqElement, ZqGroup> tau_vector = GroupVector.from(tau_mutable);

		//Compute c_A_0
		final GqElement c_A_0 = getCommitment(a_0, r_0, ck);

		//Compute diagonal products
		final GroupMatrix<ZqElement, ZqGroup> A_prepended = A.prependColumn(a_0);
		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> D = getDiagonalProducts(C_matrix, A_prepended);

		//Compute commitments to individual values of b
		final GroupVector<GqElement, GqGroup> c_B = IntStream.range(0, 2 * m)
				.mapToObj(k -> getCommitment(GroupVector.of(b_vector.get(k)), s_vector.get(k), ck))
				.collect(toGroupVector());

		//Compute re-encrypted diagonal products
		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> E =
				IntStream.range(0, 2 * m)
						.boxed()
						.flatMap(k -> Stream.of(k)
								.map(b_vector::get)
								.map(gqGroup.getGenerator()::exponentiate)
								.map(g_b_k -> constantMessage(g_b_k, l))
								.map(g_b_k_vector -> getCiphertext(g_b_k_vector, tau_vector.get(k), pk).getCiphertextProduct(D.get(k))))
						.collect(toGroupVector());

		//Compute challenge hash
		final byte[] x_bytes = hashService.recursiveHash(
				HashableBigInteger.from(gqGroup.getP()),
				HashableBigInteger.from(gqGroup.getQ()),
				pk,
				ck,
				C_matrix,
				C,
				c_A,
				c_A_0,
				c_B,
				E
		);
		final ZqElement x = ZqElement.create(byteArrayToInteger(x_bytes), zqGroup);

		//Compute as, r, b, s, tau
		final List<ZqElement> xPowers = LongStream.range(0, 2L * m)
				.mapToObj(BigInteger::valueOf)
				.map(x::exponentiate)
				.toList();

		//For all the next computations we include the first element in the sum by starting at the index 0 instead of 1. This is possible since x^0
		// is 1.
		final GroupVector<ZqElement, ZqGroup> neutralVector = Stream.generate(() -> zero)
				.limit(n)
				.collect(toGroupVector());
		final GroupVector<ZqElement, ZqGroup> a = IntStream.range(0, m + 1)
				.mapToObj(i -> vectorScalarMultiplication(xPowers.get(i), A_prepended.getColumn(i)))
				.reduce(neutralVector, MultiExponentiationArgumentService::vectorSum);

		final GroupVector<ZqElement, ZqGroup> r_vector_prepended = r_vector.prepend(r_0);
		final ZqElement r = IntStream.range(0, m + 1)
				.mapToObj(i -> xPowers.get(i).multiply(r_vector_prepended.get(i)))
				.reduce(zqGroup.getIdentity(), ZqElement::add);

		final ZqElement b = IntStream.range(0, 2 * m)
				.mapToObj(k -> xPowers.get(k).multiply(b_vector.get(k)))
				.reduce(zqGroup.getIdentity(), ZqElement::add);

		final ZqElement s = IntStream.range(0, 2 * m)
				.mapToObj(k -> xPowers.get(k).multiply(s_vector.get(k)))
				.reduce(zqGroup.getIdentity(), ZqElement::add);

		final ZqElement tau = IntStream.range(0, 2 * m)
				.mapToObj(k -> xPowers.get(k).multiply(tau_vector.get(k)))
				.reduce(zqGroup.getIdentity(), ZqElement::add);

		final MultiExponentiationArgument.Builder builder = new MultiExponentiationArgument.Builder();
		return builder
				.with_c_A_0(c_A_0)
				.with_c_B(c_B)
				.with_E(E)
				.with_a(a)
				.with_r(r)
				.with_b(b)
				.with_s(s)
				.with_tau(tau)
				.build();
	}

	@VisibleForTesting
	ElGamalMultiRecipientCiphertext multiExponentiation(final GroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> C,
			final GroupMatrix<ZqElement, ZqGroup> AMatrix, final ZqElement rho, final int m, final int l) {

		final ElGamalMultiRecipientCiphertext neutralElement = ElGamalMultiRecipientCiphertexts.neutralElement(l, gqGroup);

		final ElGamalMultiRecipientCiphertext multiExponentiationProduct = IntStream.range(0, m)
				.mapToObj(i -> {
					final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> C_i = C.getRow(i);
					//Due to 0 indexing the index i+1 in the spec on the matrix A becomes index i here
					final GroupVector<ZqElement, ZqGroup> a_i_plus_1 = AMatrix.getColumn(i);
					return getCiphertextVectorExponentiation(C_i, a_i_plus_1);
				})
				.reduce(neutralElement, ElGamalMultiRecipientCiphertext::getCiphertextProduct);

		final ElGamalMultiRecipientMessage one = ElGamalMultiRecipientMessages.ones(gqGroup, l);
		final ElGamalMultiRecipientCiphertext oneCiphertext = getCiphertext(one, rho, pk);
		return oneCiphertext.getCiphertextProduct(multiExponentiationProduct);
	}

	/**
	 * Computes the products of the diagonals of a ciphertext matrix.
	 * <p>
	 * The ciphertexts and exponents matrix must comply with the following:
	 * <ul>
	 *     <li>The ciphertexts matrix must have as many columns as the exponents matrix has rows</li>
	 *     <li>The exponents matrix must have one more column than the ciphertexts matrix has rows</li>
	 *     <li>The exponents group must have the order of the ciphertexts group</li>
	 *     <li>The ciphertexts' phis must not be larger than the elements in the public key</li>
	 *     <li>The ciphertexts and public key must be part of the same group</li>
	 * </ul>
	 *
	 * @param ciphertexts C, the ciphertexts matrix.
	 * @param exponents   A, the exponents matrix.
	 * @return A {@link GroupVector} of size 2m.
	 */
	@VisibleForTesting
	GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> getDiagonalProducts(final GroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts,
			final GroupMatrix<ZqElement, ZqGroup> exponents) {

		// Null checking.
		checkNotNull(ciphertexts);
		checkNotNull(exponents);

		// Dimensions checking.
		checkArgument(ciphertexts.numColumns() == exponents.numRows(),
				"The ciphertexts matrix must have as many columns as the exponents matrix has rows.");
		checkArgument(ciphertexts.numRows() + 1 == exponents.numColumns(),
				"The exponents matrix must have one more column than the ciphertexts matrix has rows.");
		checkArgument(ciphertexts.getElementSize() <= pk.size(),
				"There must be at least the same number of key elements than ciphertexts' phis.");

		// Group checking.
		checkArgument(pk.getGroup().equals(ciphertexts.getGroup()), "The public key and ciphertexts matrices must be part of the same group.");
		checkArgument(ciphertexts.getGroup().hasSameOrderAs(exponents.getGroup()),
				"The exponents group must have the order of the ciphertexts group.");

		//Variable reassignment
		final GroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> C = ciphertexts;
		final GroupMatrix<ZqElement, ZqGroup> A = exponents;
		final int m = C.numRows();
		final int l = C.getElementSize();

		// Algorithm.
		// Corresponds to the dk of the specifications.
		final ElGamalMultiRecipientCiphertext d_k = ElGamalMultiRecipientCiphertexts.neutralElement(l, gqGroup);

		// Compute the diagonal products D.
		return IntStream.range(0, 2 * m)
				.mapToObj(k -> {
					int lowerBound;
					int upperBound;
					if (k < m) {
						lowerBound = (m - k) - 1;
						upperBound = m;
					} else {
						lowerBound = 0;
						upperBound = 2 * m - k;
					}

					return IntStream.range(lowerBound, upperBound)
							.mapToObj(i -> {
								final int j = (k - m) + i + 1;
								final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> C_i = C.getRow(i);
								final GroupVector<ZqElement, ZqGroup> a_j = A.getColumn(j);
								return getCiphertextVectorExponentiation(C_i, a_j);
							})
							.reduce(d_k, ElGamalMultiRecipientCiphertext::getCiphertextProduct);
				})
				.collect(toGroupVector());
	}

	/**
	 * Verifies the correctness of a {@link MultiExponentiationArgument} with respect to a given {@link MultiExponentiationStatement}.
	 * <p>
	 * The statement and the argument must be non null and have compatible groups.
	 *
	 * @param statement the statement for which the argument is to be verified.
	 * @param argument  the argument to be verified.
	 * @return a {@link VerificationResult} being valid iff the argument is valid for the given statement.
	 */
	Verifiable verifyMultiExponentiationArgument(final MultiExponentiationStatement statement, final MultiExponentiationArgument argument) {
		checkNotNull(statement);
		checkNotNull(argument);

		//Group checking
		checkArgument(statement.getGroup().equals(argument.getGroup()), "Statement and argument must belong to the same group.");

		//Size checking
		checkArgument(statement.get_m() == argument.get_m(), "m dimension doesn't match.");
		checkArgument(statement.get_n() == argument.get_n(), "n dimension doesn't match.");
		checkArgument(argument.get_l() == statement.get_l(), "l dimension doesn't match.");

		//Extract variables from statement and argument
		int m = statement.get_m();
		int l = statement.get_l();
		final GroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> C_matrix = statement.get_C_matrix();
		final ElGamalMultiRecipientCiphertext C = statement.get_C();
		final GroupVector<GqElement, GqGroup> c_A = statement.get_c_A();
		final GqElement c_A_0 = argument.getc_A_0();
		final GroupVector<GqElement, GqGroup> c_B = argument.get_c_B();
		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> E = argument.get_E();
		final GroupVector<ZqElement, ZqGroup> a = argument.get_a();
		final ZqElement r = argument.get_r();
		final ZqElement b = argument.get_b();
		final ZqElement s = argument.get_s();
		final ZqElement tau = argument.get_tau();
		final BigInteger p = this.gqGroup.getP();
		final BigInteger q = this.gqGroup.getQ();

		//Algorithm
		final byte[] x_bytes = hashService.recursiveHash(
				HashableBigInteger.from(p),
				HashableBigInteger.from(q),
				pk,
				ck,
				C_matrix,
				C,
				c_A,
				c_A_0,
				c_B,
				E);

		//Hash value is guaranteed to be smaller than q
		final ZqElement x = ZqElement.create(byteArrayToInteger(x_bytes), zqGroup);

		final Verifiable verifCbm = create(() -> c_B.get(m).equals(gqGroup.getIdentity()), "cB_m must equal one.");
		final Verifiable verifEm = create(() -> E.get(m).equals(C), "E_m must equal C.");

		final Memoizer<ZqElement> xPowers = new Memoizer<>(i -> x.exponentiate(BigInteger.valueOf(i)));

		final GqElement prodCa = prodExp(c_A.prepend(c_A_0), xPowers);
		final GqElement commA = getCommitment(a, r, ck);
		final Verifiable verifA = create(() -> prodCa.equals(commA), "product Ca must equal commitment A.");

		final GqElement prodCb = prodExp(c_B, xPowers);
		final GqElement commB = getCommitment(GroupVector.of(b), s, ck);
		final Verifiable verifB = create(() -> prodCb.equals(commB), "product Cb must equal commitment B.");

		final ElGamalMultiRecipientCiphertext prodE = IntStream.range(0, E.size())
				.boxed()
				.flatMap(i -> Stream.of(i)
						.map(E::get)
						.map(E_k -> E_k.getCiphertextExponentiation(xPowers.apply(i))))
				.reduce(ElGamalMultiRecipientCiphertexts.neutralElement(l, gqGroup), ElGamalMultiRecipientCiphertext::getCiphertextProduct);
		final ElGamalMultiRecipientCiphertext encryptedGb = Stream.of(b)
				.map(gqGroup.getGenerator()::exponentiate)
				.map(g_b -> constantMessage(g_b, l))
				.map(g_b_vector -> getCiphertext(g_b_vector, tau, pk))
				.collect(onlyElement());
		final ElGamalMultiRecipientCiphertext prodC = IntStream.range(0, m)
				.boxed()
				.flatMap(i -> Stream.of(i)
						.map(__ -> xPowers.apply(m - i - 1))
						.map(x_m_minus_i_minus_1 -> vectorScalarMultiplication(x_m_minus_i_minus_1, a))
						.map(powers -> getCiphertextVectorExponentiation(C_matrix.getRow(i), powers)))
				.reduce(ElGamalMultiRecipientCiphertexts.neutralElement(l, gqGroup), ElGamalMultiRecipientCiphertext::getCiphertextProduct);
		final Verifiable verifEC = create(() -> prodE.equals(encryptedGb.getCiphertextProduct(prodC)),
				"product E must equal ciphertext product of Gb and product C.");

		return verifCbm.and(verifEm).and(verifA).and(verifB).and(verifEC);
	}

	private static GroupVector<ZqElement, ZqGroup> vectorSum(final GroupVector<ZqElement, ZqGroup> first,
			final GroupVector<ZqElement, ZqGroup> second) {
		checkNotNull(first);
		checkNotNull(second);
		checkArgument(first.size() == second.size(), "Cannot sum vectors of different dimensions.");
		checkArgument(first.getGroup().equals(second.getGroup()), "Cannot sum vectors of different groups.");
		return IntStream.range(0, first.size())
				.mapToObj(i -> first.get(i).add(second.get(i)))
				.collect(toGroupVector());
	}

	private static GroupVector<ZqElement, ZqGroup> vectorScalarMultiplication(final ZqElement value, final GroupVector<ZqElement, ZqGroup> vector) {
		return vector.stream().map(element -> element.multiply(value)).collect(toGroupVector());
	}

	/**
	 * Calculates Π<sub>i</sub> base<sub>i</sub> <sup>pow_i</sup>
	 *
	 * @param bases  the bases
	 * @param powers a function that maps from index to power
	 * @return the product of the bases exponentiated to the matching power.
	 */
	private GqElement prodExp(final GroupVector<GqElement, GqGroup> bases, final IntFunction<ZqElement> powers) {
		return IntStream.range(0, bases.size())
				.boxed()
				.flatMap(i -> Stream.of(i)
						.map(bases::get)
						.map(base -> base.exponentiate(powers.apply(i))))
				.reduce(gqGroup.getIdentity(), GqElement::multiply);
	}

	/**
	 * Thread safe memoizer for an integer indexed computation.
	 *
	 * @param <R> the output type of the computation being memoized
	 */
	private static class Memoizer<R> implements IntFunction<R> {
		private final Function<Integer, R> function;
		private final Map<Integer, R> cache = new ConcurrentHashMap<>();

		/**
		 * @param function the function to memoize.
		 */
		Memoizer(Function<Integer, R> function) {
			this.function = function;
		}

		/**
		 * Gets the result of the function applied on the input.
		 *
		 * @param input the input to the function
		 * @return the result of applying this function to the input.
		 */
		@Override
		public R apply(final int input) {
			return cache.computeIfAbsent(input, function);
		}
	}
}
