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
import static ch.post.it.evoting.cryptoprimitives.internal.mixnet.CommitmentService.getCommitmentMatrix;
import static ch.post.it.evoting.cryptoprimitives.math.GroupVector.toGroupVector;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static java.util.stream.Collectors.collectingAndThen;
import static java.util.stream.Collectors.toList;

import java.math.BigInteger;
import java.util.List;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientMessage;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableBigInteger;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableString;
import ch.post.it.evoting.cryptoprimitives.internal.elgamal.ElGamalMultiRecipientMessages;
import ch.post.it.evoting.cryptoprimitives.internal.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.internal.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.internal.utils.ConversionsInternal;
import ch.post.it.evoting.cryptoprimitives.internal.utils.Verifiable;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupMatrix;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.mixnet.MultiExponentiationArgument;
import ch.post.it.evoting.cryptoprimitives.mixnet.MultiExponentiationStatement;
import ch.post.it.evoting.cryptoprimitives.mixnet.MultiExponentiationWitness;
import ch.post.it.evoting.cryptoprimitives.mixnet.Permutation;
import ch.post.it.evoting.cryptoprimitives.mixnet.ProductArgument;
import ch.post.it.evoting.cryptoprimitives.mixnet.ProductStatement;
import ch.post.it.evoting.cryptoprimitives.mixnet.ProductWitness;
import ch.post.it.evoting.cryptoprimitives.mixnet.ShuffleArgument;
import ch.post.it.evoting.cryptoprimitives.mixnet.ShuffleStatement;
import ch.post.it.evoting.cryptoprimitives.mixnet.ShuffleWitness;
import ch.post.it.evoting.cryptoprimitives.utils.VerificationResult;

/**
 * Service to compute a cryptographic argument for the validity of a shuffle.
 *
 * <p>This class is thread safe.</p>
 */
@SuppressWarnings("java:S117")
class ShuffleArgumentService {

	private final ElGamalMultiRecipientPublicKey pk;
	private final CommitmentKey ck;

	private final RandomService randomService;
	private final HashService hashService;
	private final ProductArgumentService productArgumentService;
	private final MultiExponentiationArgumentService multiExponentiationArgumentService;

	/**
	 * Instantiates a ShuffleArgumentService with required context.
	 *
	 * @param publicKey     pk, the public key used in the recursive hash.
	 * @param commitmentKey ck, the commitment key used to compute commitments.
	 */
	ShuffleArgumentService(final ElGamalMultiRecipientPublicKey publicKey, final CommitmentKey commitmentKey, final RandomService randomService,
			final HashService hashService) {

		// Null checking.
		checkNotNull(publicKey);
		checkNotNull(commitmentKey);
		checkNotNull(randomService);
		checkNotNull(hashService);

		// Group checking.
		checkArgument(publicKey.getGroup().equals(commitmentKey.getGroup()), "The public key and commitment key must belong to the same group.");

		// Commitment key size checking
		checkArgument(commitmentKey.size() >= 2, "The commitment key must be at least of size 2.");

		// Check hash length
		final BigInteger q = publicKey.getGroup().getQ();
		checkArgument(hashService.getHashLength() * Byte.SIZE < q.bitLength(),
				"The hash service's bit length must be smaller than the bit length of q.");

		this.pk = publicKey;
		this.ck = commitmentKey;
		this.randomService = randomService;
		this.hashService = hashService;
		this.productArgumentService = new ProductArgumentService(randomService, hashService, publicKey, commitmentKey);
		this.multiExponentiationArgumentService = new MultiExponentiationArgumentService(publicKey, commitmentKey, randomService, hashService);
	}

	/**
	 * Computes a cryptographic argument for the validity of the shuffle. The statement and witness must comply with the following:
	 *
	 * <ul>
	 *     <li>be non null</li>
	 *     <li>the statement and witness values must have the same size</li>
	 *     <li>the statement's ciphertexts group and the witness's randomness group must be of the same order</li>
	 *     <li>re-encrypting and shuffling the statement ciphertexts C with the witness randomness and permutation must give the statement
	 *     ciphertexts C'</li>
	 *     <li>the size N of all inputs must satisfy N = m * n</li>
	 * </ul>
	 *
	 * @param statement the {@link ShuffleStatement} for the shuffle argument.
	 * @param witness   the {@link ShuffleWitness} for the shuffle argument.
	 * @param m         the number of rows to use for ciphertext matrices. Strictly positive integer.
	 * @param n         the number of columns to use for ciphertext matrices. Strictly greater than one.
	 * @return a {@link ShuffleArgument}.
	 */
	ShuffleArgument getShuffleArgument(final ShuffleStatement statement, final ShuffleWitness witness, final int m, final int n) {
		checkNotNull(statement);
		checkNotNull(witness);

		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> C_vector = statement.get_C();
		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> C_prime = statement.get_C_prime();
		final Permutation pi = witness.get_pi();
		final GroupVector<ZqElement, ZqGroup> rho_vector = witness.get_rho();
		final int N = pi.size();
		final int l = C_vector.getElementSize();
		final int k = pk.size();

		checkArgument(m > 0, "The number of rows for the ciphertext matrices must be strictly positive.");
		checkArgument(n > 1, "The number of columns for the ciphertext matrices must be greater than or equal to 2.");

		// Cross dimensions checking.
		checkArgument(n <= ck.size(),
				"The number of columns for the ciphertext matrices must be smaller than or equal to the commitment key size.");
		checkArgument(C_vector.size() == pi.size(), "The statement ciphertexts must have the same size as the permutation.");

		// Cross group checking.
		checkArgument(C_vector.getGroup().hasSameOrderAs(rho_vector.getGroup()),
				"The randomness group must have the order of the ciphertexts group.");

		// Ensure the statement corresponds to the witness.
		final GqGroup gqGroup = C_vector.getGroup();
		final ZqGroup zqGroup = rho_vector.getGroup();
		checkArgument(0 < l, "The ciphertexts must have at least 1 element.");
		checkArgument(l <= k, "The ciphertexts must be smaller than the public key.");

		final ElGamalMultiRecipientMessage one = ElGamalMultiRecipientMessages.ones(gqGroup, l);
		final List<ElGamalMultiRecipientCiphertext> encryptedOnes = rho_vector.stream()
				.map(rho_i -> getCiphertext(one, rho_i, pk))
				.toList();
		final List<ElGamalMultiRecipientCiphertext> C_pi = pi.stream()
				.map(C_vector::get)
				.toList();
		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> computed_C_prime = IntStream.range(0, N)
				.mapToObj(i -> encryptedOnes.get(i).getCiphertextProduct(C_pi.get(i)))
				.collect(toGroupVector());
		checkArgument(C_prime.equals(computed_C_prime),
				"The shuffled ciphertexts provided in the statement do not correspond to the re-encryption and shuffle of C under pi and rho.");

		checkArgument(N == n * m, String.format("The ciphertexts vectors must be decomposable into m * n matrices: %d != %d * %d.", N, m, n));

		// Algorithm operations.

		final BigInteger p = gqGroup.getP();
		final BigInteger q = gqGroup.getQ();

		// Compute vector r, matrix A and vector c_A
		final GroupVector<ZqElement, ZqGroup> r = randomService.genRandomVector(q, m);
		final GroupVector<ZqElement, ZqGroup> pi_vector = pi.stream()
				.map(BigInteger::valueOf)
				.map(value -> ZqElement.create(value, zqGroup))
				.collect(toGroupVector());
		final GroupMatrix<ZqElement, ZqGroup> A = pi_vector.toMatrix(m, n).transpose();
		final GroupVector<GqElement, GqGroup> c_A = getCommitmentMatrix(A, r, ck);

		// Compute x.
		final byte[] x_bytes = hashService.recursiveHash(
				HashableBigInteger.from(p),
				HashableBigInteger.from(q),
				pk,
				ck,
				C_vector,
				C_prime,
				c_A
		);
		final ZqElement x = ZqElement.create(ConversionsInternal.byteArrayToInteger(x_bytes), zqGroup);

		// Compute vector s, vector b, matrix B and vector c_B.
		final GroupVector<ZqElement, ZqGroup> s = randomService.genRandomVector(q, m);
		final GroupVector<ZqElement, ZqGroup> b_vector = pi.stream()
				.map(BigInteger::valueOf)
				.map(x::exponentiate)
				.collect(toGroupVector());
		final GroupMatrix<ZqElement, ZqGroup> B = b_vector.toMatrix(m, n).transpose();
		final GroupVector<GqElement, GqGroup> c_B = getCommitmentMatrix(B, s, ck);

		// Compute y and z.
		final byte[] y_bytes = hashService.recursiveHash(
				c_B,
				HashableBigInteger.from(p),
				HashableBigInteger.from(q),
				pk,
				ck,
				C_vector,
				C_prime,
				c_A
		);
		final ZqElement y = ZqElement.create(ConversionsInternal.byteArrayToInteger(y_bytes), zqGroup);

		final byte[] z_bytes = hashService.recursiveHash(
				HashableString.from("1"),
				c_B,
				HashableBigInteger.from(p),
				HashableBigInteger.from(q),
				pk,
				ck,
				C_vector,
				C_prime,
				c_A
		);
		final ZqElement z = ZqElement.create(ConversionsInternal.byteArrayToInteger(z_bytes), zqGroup);

		// Compute Zneg, c_{-z}.
		final GroupMatrix<ZqElement, ZqGroup> negativeZ = Stream.generate(z::negate)
				.limit(N)
				.collect(toGroupVector())
				.toMatrix(m, n)
				.transpose();
		final GroupVector<ZqElement, ZqGroup> zero = Stream.generate(zqGroup::getIdentity).limit(m).collect(toGroupVector());
		final GroupVector<GqElement, GqGroup> c_minus_z = getCommitmentMatrix(negativeZ, zero, ck);

		// Compute c_D.
		final GroupVector<GqElement, GqGroup> c_A_y = c_A.stream().map(element -> element.exponentiate(y)).collect(toGroupVector());
		final GroupVector<GqElement, GqGroup> c_D = vectorEntryWiseProduct(c_A_y, c_B);

		// Compute matrix D.
		final GroupMatrix<ZqElement, ZqGroup> yTimesA = A.rowStream()
				.map(row -> row.stream().map(y::multiply).toList())
				.collect(collectingAndThen(toList(), GroupMatrix::fromRows));
		final GroupMatrix<ZqElement, ZqGroup> D = matrixSum(yTimesA, B);

		// Compute vector t.
		final GroupVector<ZqElement, ZqGroup> t = IntStream.range(0, r.size())
				.mapToObj(i -> y.multiply(r.get(i)).add(s.get(i)))
				.collect(toGroupVector());

		// Pre-compute x^i for i=0..N used multiple times.
		final GroupVector<ZqElement, ZqGroup> xPowers = precomputeXPowers(x, N);

		// Compute b.
		final ZqElement b = computeProductB(N, y, xPowers, z, zqGroup);

		// Compute pStatement.
		final ProductStatement pStatement = new ProductStatement(vectorEntryWiseProduct(c_D, c_minus_z), b);

		// Compute pWitness.
		final GroupMatrix<ZqElement, ZqGroup> pWitnessMatrix = matrixSum(D, negativeZ);
		final ProductWitness pWitness = new ProductWitness(pWitnessMatrix, t);

		// Compute productArgument.
		final ProductArgument productArgument = productArgumentService.getProductArgument(pStatement, pWitness);

		// Compute rho.
		final ZqElement rho = IntStream.range(0, rho_vector.size())
				.mapToObj(i -> rho_vector.get(i).multiply(b_vector.get(i)))
				.reduce(zqGroup.getIdentity(), ZqElement::add)
				.negate();

		// Compute ciphertext C. The vector x is computed previously as xPowers.
		final ElGamalMultiRecipientCiphertext C = getCiphertextVectorExponentiation(C_vector, xPowers);

		// Compute mStatement.
		final MultiExponentiationStatement mStatement = new MultiExponentiationStatement(C_prime.toMatrix(m, n),
				C, c_B);

		// Compute mWitness.
		final MultiExponentiationWitness mWitness = new MultiExponentiationWitness(B, s, rho);

		// Compute multiExponentiationArgument.
		final MultiExponentiationArgument multiExponentiationArgument = multiExponentiationArgumentService
				.getMultiExponentiationArgument(mStatement, mWitness);

		final ShuffleArgument.Builder builder = new ShuffleArgument.Builder();
		return builder
				.with_c_A(c_A)
				.with_c_B(c_B)
				.with_productArgument(productArgument)
				.with_multiExponentiationArgument(multiExponentiationArgument)
				.build();
	}

	/**
	 * Verifies the correctness of a {@link ShuffleArgument} with respect to a given {@link ShuffleStatement}.
	 * <p>
	 * The statement, argument, m and n must comply with the following:
	 * <ul>
	 *     <li>the m dimension of the argument must be equal to the input parameter m</li>
	 *     <li>the statement and argument must be part of the same group</li>
	 *     <li>m * n must be equal to the statement's ciphertexts size</li>
	 * </ul>
	 *
	 * @param statement the statement for which the argument is to be verified. Non null.
	 * @param argument  the argument to be verified. Non null.
	 * @param m         the number of rows to use for ciphertext matrices. Strictly positive integer.
	 * @param n         the number of columns to use for ciphertext matrices. Strictly greater than one.
	 * @return a {@link VerificationResult} being valid iff the argument is valid for the given statement.
	 */
	VerificationResult verifyShuffleArgument(final ShuffleStatement statement, final ShuffleArgument argument, final int m, final int n) {
		checkNotNull(statement);
		checkNotNull(argument);

		checkArgument(m > 0, "The number of rows for the ciphertext matrices must be strictly positive.");
		checkArgument(n > 1, "The number of columns for the ciphertext matrices must be greater than or equal to 2.");

		// Cross dimensions checking.
		checkArgument(n <= ck.size(),
				"The number of columns for the ciphertext matrices must be smaller than or equal to the commitment key size.");
		checkArgument(m == argument.get_m(), "The m dimension of the argument must be equal to the input parameter m.");
		checkArgument(m * n == statement.get_N(), "The product m * n must be equal to the statement's ciphertexts' size.");

		// Cross group checking.
		checkArgument(statement.getGroup().equals(argument.getGroup()), "The statement and the argument must have compatible groups.");

		// Retrieve elements.
		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> C_vector = statement.get_C();
		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> C_prime = statement.get_C_prime();
		final GroupVector<GqElement, GqGroup> c_A = argument.get_c_A();
		final GroupVector<GqElement, GqGroup> c_B = argument.get_c_B();
		final ProductArgument productArgument = argument.getProductArgument();
		final MultiExponentiationArgument multiExponentiationArgument = argument.getMultiExponentiationArgument();

		checkArgument(0 < C_vector.getElementSize(), "The ciphertexts must have at least 1 element.");
		checkArgument(C_vector.getElementSize() <= pk.size(), "The ciphertexts must be smaller than the public key.");

		final GqGroup gqGroup = statement.getGroup();
		final ZqGroup zqGroup = multiExponentiationArgument.get_r().getGroup();
		final BigInteger p = gqGroup.getP();
		final BigInteger q = gqGroup.getQ();
		final int N = statement.get_N();

		// Compute x, y and z.
		final byte[] x_bytes = hashService.recursiveHash(
				HashableBigInteger.from(p),
				HashableBigInteger.from(q),
				pk,
				ck,
				C_vector,
				C_prime,
				c_A
		);
		final ZqElement x = ZqElement.create(ConversionsInternal.byteArrayToInteger(x_bytes), zqGroup);

		final byte[] y_bytes = hashService.recursiveHash(
				c_B,
				HashableBigInteger.from(p),
				HashableBigInteger.from(q),
				pk,
				ck,
				C_vector,
				C_prime,
				c_A
		);
		final ZqElement y = ZqElement.create(ConversionsInternal.byteArrayToInteger(y_bytes), zqGroup);

		final byte[] z_bytes = hashService.recursiveHash(
				HashableString.from("1"),
				c_B,
				HashableBigInteger.from(p),
				HashableBigInteger.from(q),
				pk,
				ck,
				C_vector,
				C_prime,
				c_A
		);
		final ZqElement z = ZqElement.create(ConversionsInternal.byteArrayToInteger(z_bytes), zqGroup);

		// Compute Zneg, c_{-z}.
		final GroupMatrix<ZqElement, ZqGroup> Z_neg = Stream.generate(z::negate)
				.limit(N)
				.collect(toGroupVector())
				.toMatrix(m, n)
				.transpose();
		final GroupVector<ZqElement, ZqGroup> zero = Stream.generate(zqGroup::getIdentity).limit(m).collect(toGroupVector());
		final GroupVector<GqElement, GqGroup> c_minus_z = getCommitmentMatrix(Z_neg, zero, ck);

		// Compute c_D.
		final GroupVector<GqElement, GqGroup> c_A_y = c_A.stream().map(element -> element.exponentiate(y)).collect(toGroupVector());
		final GroupVector<GqElement, GqGroup> c_D = vectorEntryWiseProduct(c_A_y, c_B);

		// Pre-compute x^i for i=0..N used multiple times.
		final GroupVector<ZqElement, ZqGroup> x_vector = precomputeXPowers(x, N);

		// Compute b.
		final ZqElement b = computeProductB(N, y, x_vector, z, zqGroup);

		// Compute pStatement.
		final ProductStatement pStatement = new ProductStatement(vectorEntryWiseProduct(c_D, c_minus_z), b);

		// Verify product argument.
		final Verifiable productVerif = productArgumentService.verifyProductArgument(pStatement, productArgument)
				.addErrorMessage("Failed to verify Product Argument.");

		// Compute ciphertext C. The vector x is computed previously as xPowers.
		final ElGamalMultiRecipientCiphertext C = getCiphertextVectorExponentiation(C_vector, x_vector);

		// Compute mStatement.
		final MultiExponentiationStatement mStatement = new MultiExponentiationStatement(C_prime.toMatrix(m, n), C, c_B);

		final Verifiable multiVerif = multiExponentiationArgumentService.verifyMultiExponentiationArgument(mStatement, multiExponentiationArgument)
				.addErrorMessage("Failed to verify MultiExponentiation Argument.");

		return productVerif.and(multiVerif).verify();
	}

	// ===============================================================================================================================================
	// Utility methods.
	// ===============================================================================================================================================

	/**
	 * Computes <code>x<sup>i</<sup></code> for <code>i</code> in <code>[0, N)</code>.
	 */
	private GroupVector<ZqElement, ZqGroup> precomputeXPowers(final ZqElement x, final int N) {
		return IntStream.range(0, N)
				.mapToObj(BigInteger::valueOf)
				.map(x::exponentiate)
				.collect(toGroupVector());
	}

	/**
	 * Computes <code>&prod;<sub>i=1</sub><sup>N</sup> (yi + x<sup>i</sup> - z)</code>.
	 */
	private ZqElement computeProductB(final int N, final ZqElement y, final GroupVector<ZqElement, ZqGroup> xPowers,
			final ZqElement z, final ZqGroup zqGroup) {

		return IntStream.range(0, N)
				.boxed()
				.flatMap(i -> Stream.of(i)
						.map(value -> ZqElement.create(value, zqGroup))
						.map(y::multiply)
						.map(elem -> elem.add(xPowers.get(i)))
						.map(elem -> elem.subtract(z)))
				.reduce(ZqElement.create(1, zqGroup), ZqElement::multiply);
	}

	/**
	 * Computes the entry-wise product of vectors {@code first} and {@code second}. The vectors must have the same size and must belong to the same
	 * GqGroup.
	 */
	private GroupVector<GqElement, GqGroup> vectorEntryWiseProduct(final GroupVector<GqElement, GqGroup> first,
			final GroupVector<GqElement, GqGroup> second) {

		checkNotNull(first);
		checkNotNull(second);
		checkArgument(first.size() == second.size());
		checkArgument(first.getGroup().equals(second.getGroup()));

		return IntStream.range(0, first.size())
				.mapToObj(i -> first.get(i).multiply(second.get(i)))
				.collect(toGroupVector());
	}

	/**
	 * Computes the entry-wise sum of matrices {@code first} and {@code second}. The matrices must have the same dimensions and belong to the same
	 * ZqGroup.
	 */
	private GroupMatrix<ZqElement, ZqGroup> matrixSum(final GroupMatrix<ZqElement, ZqGroup> first, final GroupMatrix<ZqElement, ZqGroup> second) {

		checkNotNull(first);
		checkNotNull(second);
		checkArgument(first.numRows() == second.numRows());
		checkArgument(first.numColumns() == second.numColumns());
		checkArgument(first.getGroup().equals(second.getGroup()));

		return IntStream.range(0, first.numRows())
				.mapToObj(i -> IntStream.range(0, first.numColumns())
						.mapToObj(j -> first.get(i, j).add(second.get(i, j)))
						.toList())
				.collect(collectingAndThen(toList(), GroupMatrix::fromRows));
	}

}
