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

import static ch.post.it.evoting.cryptoprimitives.GroupVector.toGroupVector;
import static ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext.getCiphertext;
import static ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext.getCiphertextVectorExponentiation;
import static ch.post.it.evoting.cryptoprimitives.mixnet.CommitmentService.getCommitmentMatrix;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static java.util.stream.Collectors.collectingAndThen;
import static java.util.stream.Collectors.toList;

import java.math.BigInteger;
import java.util.List;
import java.util.function.BooleanSupplier;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import ch.post.it.evoting.cryptoprimitives.ConversionService;
import ch.post.it.evoting.cryptoprimitives.GroupMatrix;
import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientMessage;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableBigInteger;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableString;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

/**
 * Service to compute a cryptographic argument for the validity of a shuffle.
 */
class ShuffleArgumentService {

	private final ElGamalMultiRecipientPublicKey publicKey;
	private final CommitmentKey commitmentKey;

	private final RandomService randomService;
	private final MixnetHashService hashService;
	private final ProductArgumentService productArgumentService;
	private final MultiExponentiationArgumentService multiExponentiationArgumentService;

	/**
	 * Instantiates a ShuffleArgumentService with required context.
	 *
	 * @param publicKey     pk, the public key used in the recursive hash.
	 * @param commitmentKey ck, the commitment key used to compute commitments.
	 */
	ShuffleArgumentService(final ElGamalMultiRecipientPublicKey publicKey, final CommitmentKey commitmentKey, final RandomService randomService,
			final MixnetHashService hashService) {

		// Null checking.
		checkNotNull(publicKey);
		checkNotNull(commitmentKey);
		checkNotNull(randomService);
		checkNotNull(hashService);

		// Group checking.
		checkArgument(publicKey.getGroup().equals(commitmentKey.getGroup()), "The public key and commitment key must belong to the same group.");

		this.publicKey = publicKey;
		this.commitmentKey = commitmentKey;
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
	 * @param n         the number of columns to use for ciphertext matrices. Strictly positive integer.
	 * @return a {@link ShuffleArgument}.
	 */
	ShuffleArgument getShuffleArgument(final ShuffleStatement statement, final ShuffleWitness witness, final int m, final int n) {
		checkNotNull(statement);
		checkNotNull(witness);

		checkArgument(m > 0, "The number of rows for the ciphertext matrices must be strictly positive.");
		checkArgument(n > 0, "The number of columns for the ciphertext matrices must be strictly positive.");

		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertextsC = statement.getCiphertexts();
		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> shuffledCiphertextsCPrime = statement.getShuffledCiphertexts();
		final Permutation permutation = witness.getPermutation();
		final GroupVector<ZqElement, ZqGroup> randomness = witness.getRandomness();

		// Cross dimensions checking.
		checkArgument(ciphertextsC.size() == permutation.getSize(),
				"The statement ciphertexts must have the same size as the permutation.");

		// Cross group checking.
		checkArgument(ciphertextsC.getGroup().hasSameOrderAs(randomness.getGroup()),
				"The randomness group must have the order of the ciphertexts group.");

		// Ensure the statement corresponds to the witness.
		final GqGroup gqGroup = ciphertextsC.getGroup();
		final ZqGroup zqGroup = randomness.getGroup();
		final int N = permutation.getSize();
		final int l = ciphertextsC.get(0).size();

		checkArgument(l <= publicKey.size(), "The ciphertexts must be smaller than the public key.");

		final ElGamalMultiRecipientMessage ones = ElGamalMultiRecipientMessage.ones(gqGroup, l);
		final List<ElGamalMultiRecipientCiphertext> encryptedOnes = randomness.stream()
				.map(rho -> getCiphertext(ones, rho, publicKey))
				.collect(toList());
		final List<ElGamalMultiRecipientCiphertext> shuffledCiphertexts = permutation.stream()
				.mapToObj(ciphertextsC::get)
				.collect(toList());
		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> computedShuffledCiphertextsCPrime = IntStream.range(0, N)
				.mapToObj(i -> encryptedOnes.get(i).multiply(shuffledCiphertexts.get(i)))
				.collect(toGroupVector());
		checkArgument(shuffledCiphertextsCPrime.equals(computedShuffledCiphertextsCPrime),
				"The shuffled ciphertexts provided in the statement do not correspond to the re-encryption and shuffle of C under pi and rho.");

		checkArgument(N == n * m, String.format("The ciphertexts vectors must be decomposable into m * n matrices: %d != %d * %d.", N, m, n));

		// Algorithm operations.

		final BigInteger p = gqGroup.getP();
		final BigInteger q = gqGroup.getQ();

		// Compute vector r, matrix A and vector c_A
		final GroupVector<ZqElement, ZqGroup> r = randomService.genRandomVector(q, m);
		final GroupVector<ZqElement, ZqGroup> permutationVector = permutation.stream()
				.mapToObj(BigInteger::valueOf)
				.map(value -> ZqElement.create(value, zqGroup))
				.collect(toGroupVector());
		final GroupMatrix<ZqElement, ZqGroup> matrixA = permutationVector.toMatrix(m, n).transpose();
		final GroupVector<GqElement, GqGroup> cA = getCommitmentMatrix(matrixA, r, commitmentKey);

		// Compute x.
		final byte[] xHash = hashService.recursiveHash(
				HashableBigInteger.from(p),
				HashableBigInteger.from(q),
				publicKey,
				commitmentKey,
				ciphertextsC,
				shuffledCiphertextsCPrime,
				cA
		);
		final ZqElement x = ZqElement.create(ConversionService.byteArrayToInteger(xHash), zqGroup);

		// Compute vector s, vector b, matrix B and vector c_B.
		final GroupVector<ZqElement, ZqGroup> s = randomService.genRandomVector(q, m);
		final GroupVector<ZqElement, ZqGroup> bVector = permutation.stream()
				.mapToObj(BigInteger::valueOf)
				.map(x::exponentiate)
				.collect(toGroupVector());
		final GroupMatrix<ZqElement, ZqGroup> matrixB = bVector.toMatrix(m, n).transpose();
		final GroupVector<GqElement, GqGroup> cB = getCommitmentMatrix(matrixB, s, commitmentKey);

		// Compute y and z.
		final byte[] yHash = hashService.recursiveHash(
				cB,
				HashableBigInteger.from(p),
				HashableBigInteger.from(q),
				publicKey,
				commitmentKey,
				ciphertextsC,
				shuffledCiphertextsCPrime,
				cA
		);
		final ZqElement y = ZqElement.create(ConversionService.byteArrayToInteger(yHash), zqGroup);

		final byte[] zHash = hashService.recursiveHash(
				HashableString.from("1"),
				cB,
				HashableBigInteger.from(p),
				HashableBigInteger.from(q),
				publicKey,
				commitmentKey,
				ciphertextsC,
				shuffledCiphertextsCPrime,
				cA
		);
		final ZqElement z = ZqElement.create(ConversionService.byteArrayToInteger(zHash), zqGroup);

		// Compute Zneg, c_{-z}.
		final GroupMatrix<ZqElement, ZqGroup> negativeZ = Stream.generate(z::negate)
				.limit(N)
				.collect(toGroupVector())
				.toMatrix(m, n)
				.transpose();
		final GroupVector<ZqElement, ZqGroup> zeros = Stream.generate(zqGroup::getIdentity).limit(m).collect(toGroupVector());
		final GroupVector<GqElement, GqGroup> cNegativeZ = getCommitmentMatrix(negativeZ, zeros, commitmentKey);

		// Compute c_D.
		final GroupVector<GqElement, GqGroup> cAPowY = cA.stream().map(element -> element.exponentiate(y)).collect(toGroupVector());
		final GroupVector<GqElement, GqGroup> cD = vectorEntryWiseProduct(cAPowY, cB);

		// Compute matrix D.
		final GroupMatrix<ZqElement, ZqGroup> yTimesA = matrixA.rowStream()
				.map(row -> row.stream().map(y::multiply).collect(toList()))
				.collect(collectingAndThen(toList(), GroupMatrix::fromRows));
		final GroupMatrix<ZqElement, ZqGroup> matrixD = matrixSum(yTimesA, matrixB);

		// Compute vector t.
		final GroupVector<ZqElement, ZqGroup> t = IntStream.range(0, r.size())
				.mapToObj(i -> y.multiply(r.get(i)).add(s.get(i)))
				.collect(toGroupVector());

		// Pre-compute x^i for i=0..N used multiple times.
		final GroupVector<ZqElement, ZqGroup> xPowers = precomputeXPowers(x, N);

		// Compute b.
		final ZqElement b = computeProductB(N, y, xPowers, z, zqGroup);

		// Compute pStatement.
		final ProductStatement pStatement = new ProductStatement(vectorEntryWiseProduct(cD, cNegativeZ), b);

		// Compute pWitness.
		final GroupMatrix<ZqElement, ZqGroup> pWitnessMatrix = matrixSum(matrixD, negativeZ);
		final ProductWitness pWitness = new ProductWitness(pWitnessMatrix, t);

		// Compute productArgument.
		final ProductArgument productArgument = productArgumentService.getProductArgument(pStatement, pWitness);

		// Compute rho.
		final ZqElement rho = IntStream.range(0, randomness.size())
				.mapToObj(i -> randomness.get(i).multiply(bVector.get(i)))
				.reduce(zqGroup.getIdentity(), ZqElement::add)
				.negate();

		// Compute ciphertext C. The vector x is computed previously as xPowers.
		final ElGamalMultiRecipientCiphertext ciphertextC = getCiphertextVectorExponentiation(ciphertextsC, xPowers);

		// Compute mStatement.
		final MultiExponentiationStatement mStatement = new MultiExponentiationStatement(shuffledCiphertextsCPrime.toMatrix(m, n),
				ciphertextC, cB);

		// Compute mWitness.
		final MultiExponentiationWitness mWitness = new MultiExponentiationWitness(matrixB, s, rho);

		// Compute multiExponentiationArgument.
		final MultiExponentiationArgument multiExponentiationArgument = multiExponentiationArgumentService
				.getMultiExponentiationArgument(mStatement, mWitness);

		final ShuffleArgument.Builder builder = new ShuffleArgument.Builder();
		return builder
				.withCA(cA)
				.withCB(cB)
				.withProductArgument(productArgument)
				.withMultiExponentiationArgument(multiExponentiationArgument)
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
	 * @param n         the number of columns to use for ciphertext matrices. Strictly positive integer.
	 * @return <b>true</b> if the argument is valid for the given statement, <b>false</b> otherwise.
	 */
	boolean verifyShuffleArgument(final ShuffleStatement statement, final ShuffleArgument argument, final int m, final int n) {
		checkNotNull(statement);
		checkNotNull(argument);

		checkArgument(m > 0, "The number of rows for the ciphertext matrices must be strictly positive.");
		checkArgument(n > 0, "The number of columns for the ciphertext matrices must be strictly positive.");

		// Cross dimensions checking.
		checkArgument(m == argument.getM(), "The m dimension of the argument must be equal to the input parameter m.");
		checkArgument(m * n == statement.getN(), "The product m * n must be equal to the statement's ciphertexts' size.");

		// Cross group checking.
		checkArgument(statement.getGroup().equals(argument.getGroup()), "The statement and the argument must have compatible groups.");

		// Retrieve elements.
		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertextsC = statement.getCiphertexts();
		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> shuffledCiphertextsCPrime = statement.getShuffledCiphertexts();
		final GroupVector<GqElement, GqGroup> cA = argument.getcA();
		final GroupVector<GqElement, GqGroup> cB = argument.getcB();
		final ProductArgument productArgument = argument.getProductArgument();
		final MultiExponentiationArgument multiExponentiationArgument = argument.getMultiExponentiationArgument();

		final GqGroup gqGroup = statement.getGroup();
		final ZqGroup zqGroup = multiExponentiationArgument.getR().getGroup();
		final BigInteger p = gqGroup.getP();
		final BigInteger q = gqGroup.getQ();
		final int N = statement.getN();

		// Compute x, y and z.
		final byte[] xHash = hashService.recursiveHash(
				HashableBigInteger.from(p),
				HashableBigInteger.from(q),
				publicKey,
				commitmentKey,
				ciphertextsC,
				shuffledCiphertextsCPrime,
				cA
		);
		final ZqElement x = ZqElement.create(ConversionService.byteArrayToInteger(xHash), zqGroup);

		final byte[] yHash = hashService.recursiveHash(
				cB,
				HashableBigInteger.from(p),
				HashableBigInteger.from(q),
				publicKey,
				commitmentKey,
				ciphertextsC,
				shuffledCiphertextsCPrime,
				cA
		);
		final ZqElement y = ZqElement.create(ConversionService.byteArrayToInteger(yHash), zqGroup);

		final byte[] zHash = hashService.recursiveHash(
				HashableString.from("1"),
				cB,
				HashableBigInteger.from(p),
				HashableBigInteger.from(q),
				publicKey,
				commitmentKey,
				ciphertextsC,
				shuffledCiphertextsCPrime,
				cA
		);
		final ZqElement z = ZqElement.create(ConversionService.byteArrayToInteger(zHash), zqGroup);

		// Compute Zneg, c_{-z}.
		final GroupMatrix<ZqElement, ZqGroup> negativeZ = Stream.generate(z::negate)
				.limit(N)
				.collect(toGroupVector())
				.toMatrix(m, n)
				.transpose();
		final GroupVector<ZqElement, ZqGroup> zeros = Stream.generate(zqGroup::getIdentity).limit(m).collect(toGroupVector());
		final GroupVector<GqElement, GqGroup> cNegativeZ = getCommitmentMatrix(negativeZ, zeros, commitmentKey);

		// Compute c_D.
		final GroupVector<GqElement, GqGroup> cAPowY = cA.stream().map(element -> element.exponentiate(y)).collect(toGroupVector());
		final GroupVector<GqElement, GqGroup> cD = vectorEntryWiseProduct(cAPowY, cB);

		// Pre-compute x^i for i=0..N used multiple times.
		final GroupVector<ZqElement, ZqGroup> xPowers = precomputeXPowers(x, N);

		// Compute b.
		final ZqElement b = computeProductB(N, y, xPowers, z, zqGroup);

		// Compute pStatement.
		final ProductStatement pStatement = new ProductStatement(vectorEntryWiseProduct(cD, cNegativeZ), b);

		// Verify product argument.
		final BooleanSupplier productVerif = () -> productArgumentService.verifyProductArgument(pStatement, productArgument);

		// Compute ciphertext C. The vector x is computed previously as xPowers.
		final ElGamalMultiRecipientCiphertext ciphertextC = getCiphertextVectorExponentiation(ciphertextsC, xPowers);

		// Compute mStatement.
		final MultiExponentiationStatement mStatement = new MultiExponentiationStatement(shuffledCiphertextsCPrime.toMatrix(m, n),
				ciphertextC, cB);

		final BooleanSupplier multiVerif = () -> multiExponentiationArgumentService
				.verifyMultiExponentiationArgument(mStatement, multiExponentiationArgument);

		return productVerif.getAsBoolean() && multiVerif.getAsBoolean();
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
						.collect(toList()))
				.collect(collectingAndThen(toList(), GroupMatrix::fromRows));
	}

}
