/*
 * Copyright 2021 Post CH Ltd
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
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static ch.post.it.evoting.cryptoprimitives.ConversionService.byteArrayToInteger;
import static ch.post.it.evoting.cryptoprimitives.GroupVector.toGroupVector;
import static ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext.getCiphertext;
import static ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext.getCiphertextVectorExponentiation;
import static ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientMessage.constantMessage;
import static ch.post.it.evoting.cryptoprimitives.mixnet.CommitmentService.getCommitment;
import static ch.post.it.evoting.cryptoprimitives.mixnet.CommitmentService.getCommitmentMatrix;
import static ch.post.it.evoting.cryptoprimitives.mixnet.Verifiable.create;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
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
import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.GroupMatrix;
import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientMessage;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.hashing.BoundedHashService;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableBigInteger;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

/**
 * Service to generate multi exponentiation arguments.
 */
final class MultiExponentiationArgumentService {

	private final ElGamalMultiRecipientPublicKey pk;
	private final CommitmentKey ck;
	private final RandomService randomService;
	private final BoundedHashService hashService;
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
			final RandomService randomService, final BoundedHashService hashService) {

		// Null checking.
		checkNotNull(publicKey);
		checkNotNull(commitmentKey);
		checkNotNull(randomService);
		checkNotNull(hashService);

		// Group checking.
		checkArgument(publicKey.getGroup().equals(commitmentKey.getGroup()), "The public key and commitment key must belong to the same group");

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

		//Group checking
		checkArgument(this.gqGroup.equals(statement.getGroup()), "The statement must belong to the same group as the public key and commitment key.");
		checkArgument(this.gqGroup.hasSameOrderAs(witness.getGroup()), "The witness must belong to a ZqGroup of order q.");
		final BigInteger q = this.gqGroup.getQ();

		//Dimension checking
		final GroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> CMatrix = statement.getCMatrix();
		final ElGamalMultiRecipientCiphertext CCiphertext = statement.getC();
		final GroupVector<GqElement, GqGroup> cA = statement.getcA();
		final GroupMatrix<ZqElement, ZqGroup> AMatrix = witness.getA();
		final GroupVector<ZqElement, ZqGroup> rVector = witness.getR();
		final ZqElement rho = witness.getRho();

		checkArgument(statement.getN() == witness.getDimensionN(), "Statement and witness do not have compatible n dimension.");
		checkArgument(statement.getM() == witness.getDimensionM(), "Statement and witness do not have compatible m dimension.");
		checkArgument(witness.getDimensionN() <= ck.size(),
				"The number of rows of matrix A must be smaller or equal to the size of the commitment key.");

		final int m = statement.getM();
		final int n = statement.getN();
		final int l = CMatrix.isEmpty() ? 0 : CMatrix.getElementSize();

		checkArgument(l <= pk.size(), "The ciphertexts must be smaller than the public key.");

		//Ensure that C is the result of the re-encryption and multi exponentiation of matrix C with exponents matrix A
		final ElGamalMultiRecipientCiphertext computedCCiphertext = multiExponentiation(CMatrix, AMatrix, rho, m, l);
		checkArgument(CCiphertext.equals(computedCCiphertext),
				"The computed multi exponentiation ciphertext does not correspond to the one provided in the statement.");

		//Ensure that cA is the commitment to matrix A
		checkArgument(cA.equals(getCommitmentMatrix(AMatrix, rVector, ck)), "The commitment provided does not correspond to the matrix A.");

		//Algorithm
		//Generate a0, r0, bs, ss, taus,
		final GroupVector<ZqElement, ZqGroup> a0 = randomService.genRandomVector(q, n);
		final ZqElement r0 = ZqElement.create(randomService.genRandomInteger(q), zqGroup);
		final List<ZqElement> mutableBs = new ArrayList<>(randomService.genRandomVector(q, 2 * m));
		final List<ZqElement> mutableSs = new ArrayList<>(randomService.genRandomVector(q, 2 * m));
		final List<ZqElement> mutableTaus = new ArrayList<>(randomService.genRandomVector(q, 2 * m));
		final ZqElement zero = ZqElement.create(0, zqGroup);
		mutableBs.set(m, zero);
		mutableSs.set(m, zero);
		mutableTaus.set(m, rho);
		final GroupVector<ZqElement, ZqGroup> bVector = GroupVector.from(mutableBs);
		final GroupVector<ZqElement, ZqGroup> sVector = GroupVector.from(mutableSs);
		final GroupVector<ZqElement, ZqGroup> tauVector = GroupVector.from(mutableTaus);

		//Compute cA0
		final GqElement cA0 = getCommitment(a0, r0, ck);

		//Compute diagonal products
		final GroupMatrix<ZqElement, ZqGroup> prependedAMatrix = AMatrix.prependColumn(a0);
		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> diagonalProducts = getDiagonalProducts(CMatrix, prependedAMatrix);

		//Compute commitments to individual values of b
		final GroupVector<GqElement, GqGroup> cBVector = IntStream.range(0, 2 * m)
				.mapToObj(k -> getCommitment(GroupVector.of(bVector.get(k)), sVector.get(k), ck))
				.collect(toGroupVector());

		//Compute re-encrypted diagonal products
		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> EVector =
				IntStream.range(0, 2 * m)
						.boxed()
						.flatMap(k -> Stream.of(k)
								.map(bVector::get)
								.map(gqGroup.getGenerator()::exponentiate)
								.map(gPowBk -> constantMessage(gPowBk, l))
								.map(gPowBkMessage -> getCiphertext(gPowBkMessage, tauVector.get(k), pk)
										.multiply(diagonalProducts.get(k))))
						.collect(toGroupVector());

		//Compute challenge hash
		final byte[] hash = hashService.recursiveHash(
				HashableBigInteger.from(gqGroup.getP()),
				HashableBigInteger.from(gqGroup.getQ()),
				pk,
				ck,
				CMatrix,
				CCiphertext,
				cA,
				cA0,
				cBVector,
				EVector
		);
		final ZqElement x = ZqElement.create(byteArrayToInteger(hash), zqGroup);

		//Compute as, r, b, s, tau
		final ImmutableList<ZqElement> xPowI = LongStream.range(0, 2L * m)
				.mapToObj(BigInteger::valueOf)
				.map(x::exponentiate)
				.collect(toImmutableList());

		//For all the next computations we include the first element in the sum by starting at the index 0 instead of 1. This is possible since x^0
		// is 1.
		final GroupVector<ZqElement, ZqGroup> neutralVector = Stream.generate(() -> zero)
				.limit(n)
				.collect(toGroupVector());
		final GroupVector<ZqElement, ZqGroup> aVector = IntStream.range(0, m + 1)
				.mapToObj(i -> vectorScalarMultiplication(xPowI.get(i), prependedAMatrix.getColumn(i)))
				.reduce(neutralVector, MultiExponentiationArgumentService::vectorSum);

		final GroupVector<ZqElement, ZqGroup> prependedrVector = rVector.prepend(r0);
		final ZqElement r = IntStream.range(0, m + 1)
				.mapToObj(i -> xPowI.get(i).multiply(prependedrVector.get(i)))
				.reduce(zqGroup.getIdentity(), ZqElement::add);

		final ZqElement b = IntStream.range(0, 2 * m)
				.mapToObj(k -> xPowI.get(k).multiply(bVector.get(k)))
				.reduce(zqGroup.getIdentity(), ZqElement::add);

		final ZqElement s = IntStream.range(0, 2 * m)
				.mapToObj(k -> xPowI.get(k).multiply(sVector.get(k)))
				.reduce(zqGroup.getIdentity(), ZqElement::add);

		final ZqElement tau = IntStream.range(0, 2 * m)
				.mapToObj(k -> xPowI.get(k).multiply(tauVector.get(k)))
				.reduce(zqGroup.getIdentity(), ZqElement::add);

		final MultiExponentiationArgument.Builder builder = new MultiExponentiationArgument.Builder();
		return builder
				.withcA0(cA0)
				.withcBVector(cBVector)
				.withEVector(EVector)
				.withaVector(aVector)
				.withr(r)
				.withb(b)
				.withs(s)
				.withtau(tau)
				.build();
	}

	@VisibleForTesting
	ElGamalMultiRecipientCiphertext multiExponentiation(final GroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> CMatrix,
			final GroupMatrix<ZqElement, ZqGroup> AMatrix, final ZqElement rho, final int m, final int ciphertextSize) {

		final ElGamalMultiRecipientCiphertext neutralElement = ElGamalMultiRecipientCiphertext.neutralElement(ciphertextSize, gqGroup);
		//Due to 0 indexing the index i+1 in the spec on the matrix A becomes index i here
		final ElGamalMultiRecipientCiphertext multiExponentiationProduct = IntStream.range(0, m)
				.mapToObj(i -> getCiphertextVectorExponentiation(CMatrix.getRow(i), AMatrix.getColumn(i)))
				.reduce(neutralElement, ElGamalMultiRecipientCiphertext::multiply);

		final ElGamalMultiRecipientMessage ones = ElGamalMultiRecipientMessage.ones(gqGroup, ciphertextSize);
		final ElGamalMultiRecipientCiphertext onesCiphertext = getCiphertext(ones, rho, pk);
		return onesCiphertext.multiply(multiExponentiationProduct);
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

		// Empty matrices handling.
		checkArgument(!ciphertexts.isEmpty() && !exponents.isEmpty(), "The ciphertexts and exponents matrices cannot be empty.");

		// Dimensions checking.
		checkArgument(ciphertexts.numColumns() == exponents.numRows(),
				"The ciphertexts matrix must have as many columns as the exponents matrix has rows.");
		checkArgument(ciphertexts.numRows() + 1 == exponents.numColumns(),
				"The exponents matrix must have one more column than the ciphertexts matrix has rows.");
		checkArgument(ciphertexts.get(0, 0).size() <= this.pk.size(),
				"There must be at least the same number of key elements than ciphertexts' phis.");

		// Group checking.
		checkArgument(pk.getGroup().equals(ciphertexts.getGroup()), "The public key and ciphertexts matrices must be part of the same group.");
		checkArgument(ciphertexts.getGroup().hasSameOrderAs(exponents.getGroup()),
				"The exponents group must have the order of the ciphertexts group.");

		// Algorithm.

		final int m = ciphertexts.numRows();
		final int l = ciphertexts.get(0, 0).size();

		// Corresponds to the dk of the specifications.
		final ElGamalMultiRecipientCiphertext ciphertextMultiplicationIdentity = ElGamalMultiRecipientCiphertext.neutralElement(l, gqGroup);

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
								final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertextRowI = ciphertexts.getRow(i);
								final GroupVector<ZqElement, ZqGroup> exponentsColumnJ = exponents.getColumn(j);
								return ElGamalMultiRecipientCiphertext.getCiphertextVectorExponentiation(ciphertextRowI, exponentsColumnJ);
							})
							.reduce(ciphertextMultiplicationIdentity, ElGamalMultiRecipientCiphertext::multiply);
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
		checkArgument(statement.getM() == argument.getM(), "m dimension doesn't match.");
		checkArgument(statement.getN() == argument.getN(), "n dimension doesn't match.");
		checkArgument(statement.getL() == argument.getL(), "l dimension doesn't match.");

		//Extract variables from statement and argument
		int m = statement.getM();
		int l = statement.getL();
		final GroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> CMatrix = statement.getCMatrix();
		final ElGamalMultiRecipientCiphertext C = statement.getC();
		final GroupVector<GqElement, GqGroup> cA = statement.getcA();

		final GqElement cA0 = argument.getcA0();
		final GroupVector<GqElement, GqGroup> cBVector = argument.getcBVector();
		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> EVector = argument.getEVector();
		final GroupVector<ZqElement, ZqGroup> aVector = argument.getaVector();
		final ZqElement r = argument.getR();
		final ZqElement b = argument.getB();
		final ZqElement s = argument.getS();
		final ZqElement tau = argument.getTau();

		//Algorithm
		final byte[] hash = hashService.recursiveHash(
				HashableBigInteger.from(this.gqGroup.getP()),
				HashableBigInteger.from(this.gqGroup.getQ()),
				this.pk,
				this.ck,
				CMatrix,
				C,
				cA,
				cA0,
				cBVector,
				EVector);

		//Hash value is guaranteed to be smaller than q
		final ZqElement x = ZqElement.create(byteArrayToInteger(hash), zqGroup);

		final Verifiable verifCbm = create(() -> cBVector.get(m).equals(gqGroup.getIdentity()), "cB_m must equal one.");
		final Verifiable verifEm = create(() -> EVector.get(m).equals(C), "E_m must equal C.");

		final Memoizer<ZqElement> xPowI = new Memoizer<>(i -> x.exponentiate(BigInteger.valueOf(i)));

		final GqElement prodCa = prodExp(cA.prepend(cA0), xPowI);
		final GqElement commA = getCommitment(aVector, r, ck);
		final Verifiable verifA = create(() -> prodCa.equals(commA), "product Ca must equal commitment A.");

		final GqElement prodCb = prodExp(cBVector, xPowI);
		final GqElement commB = getCommitment(GroupVector.of(b), s, ck);
		final Verifiable verifB = create(() -> prodCb.equals(commB), "product Cb must equal commitment B.");

		final ElGamalMultiRecipientCiphertext prodE = IntStream.range(0, EVector.size())
				.boxed()
				.flatMap(i -> Stream.of(i)
						.map(EVector::get)
						.map(Ek -> Ek.exponentiate(xPowI.apply(i))))
				.reduce(ElGamalMultiRecipientCiphertext.neutralElement(l, gqGroup), ElGamalMultiRecipientCiphertext::multiply);
		final ElGamalMultiRecipientCiphertext encryptedGb = Stream.of(b)
				.map(gqGroup.getGenerator()::exponentiate)
				.map(gPowB -> constantMessage(gPowB, l))
				.map(gPowBMessage -> getCiphertext(gPowBMessage, tau, pk))
				.collect(onlyElement());
		final ElGamalMultiRecipientCiphertext prodC = IntStream.range(0, m)
				.boxed()
				.flatMap(j -> Stream.of(j)
						.map(i -> xPowI.apply(m - i - 1))
						.map(xExponentiated -> vectorScalarMultiplication(xExponentiated, aVector))
						.map(powers -> getCiphertextVectorExponentiation(CMatrix.getRow(j), powers)))
				.reduce(ElGamalMultiRecipientCiphertext.neutralElement(l, gqGroup), ElGamalMultiRecipientCiphertext::multiply);
		final Verifiable verifEC = create(() -> prodE.equals(encryptedGb.multiply(prodC)),
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
	 * Thread safe memoizer for a integer indexed computation.
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
