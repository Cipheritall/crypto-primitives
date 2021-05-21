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
import static ch.post.it.evoting.cryptoprimitives.mixnet.CommitmentService.getCommitment;
import static ch.post.it.evoting.cryptoprimitives.mixnet.CommitmentService.getCommitmentMatrix;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.stream.IntStream;

import ch.post.it.evoting.cryptoprimitives.GroupMatrix;
import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

final class ProductArgumentService {

	private final RandomService randomService;
	private final CommitmentKey commitmentKey;
	private final HadamardArgumentService hadamardArgumentService;
	private final SingleValueProductArgumentService singleValueProductArgumentService;

	/**
	 * Constructs a ProductArgumentService.
	 *
	 * @param randomService the random service to be used for random integer generation.
	 * @param hashService   the hash service that provides the recursive hash function to be used.
	 * @param publicKey     the public key.
	 * @param commitmentKey the commitment key to be used for commitments.
	 */
	ProductArgumentService(final RandomService randomService, final HashService hashService, final ElGamalMultiRecipientPublicKey publicKey,
			final CommitmentKey commitmentKey) {
		checkNotNull(randomService);
		checkNotNull(hashService);
		checkNotNull(publicKey);
		checkNotNull(commitmentKey);

		// Group checking
		checkArgument(publicKey.getGroup().equals(commitmentKey.getGroup()),
				"The public key and the commitment key must have the same group.");

		// Check hash length
		final BigInteger q = publicKey.getGroup().getQ();
		checkArgument(hashService.getHashLength() * Byte.SIZE < q.bitLength(),
				"The hash service's bit length must be smaller than the bit length of q.");

		this.randomService = randomService;
		this.commitmentKey = commitmentKey;
		this.hadamardArgumentService = new HadamardArgumentService(this.randomService, hashService, publicKey, this.commitmentKey);
		this.singleValueProductArgumentService = new SingleValueProductArgumentService(this.randomService, hashService, publicKey,
				this.commitmentKey);
	}

	/**
	 * Calculates a {@link ProductArgument}.
	 * <p>
	 * The statement and witness must comply with the following:
	 * <ul>
	 *     <li>be non null</li>
	 *     <li>the commitments to matrix A and the exponent vector r must have the same size</li>
	 *     <li>the matrix' number of rows must not be greater than the commitment key size</li>
	 *     <li>the product b and the matrix A must belong to the same group</li>
	 *     <li>the commitments to A and the commitment key must belong to the same group</li>
	 *     <li>the matrix A must have two or more columns</li>
	 *     <li>c<sub>A</sub> = getCommitmentMatrix(A, r, ck)</li>
	 *     <li>b = &prod;<sub>i,j</sub> a<sub>i,j</sub> mod q</li>
	 * </ul>
	 *
	 * @param statement the {@link ProductStatement}
	 * @param witness   the {@link ProductWitness}
	 * @return a {@link ProductArgument}
	 */
	ProductArgument getProductArgument(final ProductStatement statement, final ProductWitness witness) {
		checkNotNull(statement);
		checkNotNull(witness);

		final GroupVector<GqElement, GqGroup> cA = statement.getCommitments();
		final ZqElement b = statement.getProduct();
		@SuppressWarnings("squid:S00117")
		final GroupMatrix<ZqElement, ZqGroup> A = witness.getMatrix();
		final GroupVector<ZqElement, ZqGroup> r = witness.getExponents();

		// Dimension check
		checkArgument(cA.size() == r.size(), "The commitments A and the exponents r must have the same size.");
		checkArgument(0 < A.numColumns(), "The number of columns m must be strictly positive.");
		checkArgument(1 < A.numRows(), "The number of rows n must be greater than or equal to 2.");
		checkArgument(A.numRows() <= commitmentKey.size(),
				"The matrix' number of rows cannot be greater than the commitment key size.");

		// Group check
		checkArgument(b.getGroup().equals(A.getGroup()), "The product b and the matrix A must belong to the same group.");
		checkArgument(commitmentKey.getGroup().equals(cA.getGroup()), "The commitment key and the commitments must have the same group.");

		// Ensure that the statement and the witness are compatible
		final int n = A.numRows();
		final int m = A.numColumns();
		checkArgument(cA.equals(getCommitmentMatrix(A, r, commitmentKey)),
				"The commitment to matrix A with exponents r using the given commitment key must yield the commitments cA.");
		final ZqGroup zqGroup = A.getGroup();
		// Create the neutral element for the multiplication
		final ZqElement one = ZqElement.create(1, zqGroup);
		checkArgument(b.equals(A.stream().reduce(one, ZqElement::multiply)), "The product of all elements in matrix A must be equal to b.");

		// Start of the operations
		final BigInteger q = zqGroup.getQ();

		if (m > 1) {
			// If m > 1, the ciphertexts can be arranged into a multi-column matrix.
			// In that case, the Product Argument consists of a Hadamard Argument and a Single Value Product Argument.

			final ZqElement s = ZqElement.create(randomService.genRandomInteger(q), zqGroup);
			final GroupVector<ZqElement, ZqGroup> biList = IntStream.range(0, n)
					.mapToObj(i -> IntStream.range(0, m)
							.mapToObj(j -> A.get(i, j))
							.reduce(one, ZqElement::multiply))
					.collect(toGroupVector());
			final GqElement cb = getCommitment(biList, s, commitmentKey);

			// Get the Hadamard argument
			final HadamardStatement hStatement = new HadamardStatement(cA, cb);
			final HadamardWitness hWitness = new HadamardWitness(A, biList, r, s);
			final HadamardArgument hadamardArgument = hadamardArgumentService.getHadamardArgument(hStatement, hWitness);

			// Get the single value product argument
			final SingleValueProductStatement sStatement = new SingleValueProductStatement(cb, b);
			final SingleValueProductWitness sWitness = new SingleValueProductWitness(biList, s);
			final SingleValueProductArgument singleValueProdArgument = singleValueProductArgumentService
					.getSingleValueProductArgument(sStatement, sWitness);

			return new ProductArgument(cb, hadamardArgument, singleValueProdArgument);
		} else {
			// If m = 1, the number of ciphertexts is prime and they cannot be arranged into a multi-column matrix.
			// In that case, we omit the Hadamard Argument and return a Single Value Product Argument only.

			// Get the single value product argument
			final SingleValueProductStatement sStatement = new SingleValueProductStatement(cA.get(0), b);
			final SingleValueProductWitness sWitness = new SingleValueProductWitness(A.getColumn(0), r.get(0));
			final SingleValueProductArgument singleValueProdArgument = singleValueProductArgumentService
					.getSingleValueProductArgument(sStatement, sWitness);

			return new ProductArgument(singleValueProdArgument);
		}
	}

	/**
	 * Verifies the correctness of a {@link ProductArgument} with respect to a given {@link ProductStatement}.
	 *
	 * @param statement the statement for which the argument is to be verified.
	 * @param argument  the argument to be verified.
	 * @return a {@link VerificationResult} being valid iff the argument is valid for the given statement.
	 */
	Verifiable verifyProductArgument(final ProductStatement statement, final ProductArgument argument) {
		checkNotNull(statement, "The statement must be non-null.");
		checkNotNull(argument, "The argument must be non-null.");

		final GroupVector<GqElement, GqGroup> cA = statement.getCommitments();
		final ZqElement b = statement.getProduct();
		final int m = statement.getM();

		final SingleValueProductArgument sArgument = argument.getSingleValueProductArgument();

		// cross-check groups and dimensions
		checkArgument(statement.getGroup().equals(sArgument.getGroup()),
				"The statement and the argument must have compatible groups.");
		checkArgument(statement.getM() == argument.getM(),
				"The statement and the argument must have the same m.");

		if (m > 1) {
			final GqElement cb = argument.getCommitmentB()
					.orElseThrow(() -> new IllegalArgumentException("The product argument must contain a commitment b for m > 1."));
			final HadamardArgument hArgument = argument.getHadamardArgument()
					.orElseThrow(() -> new IllegalArgumentException("The product argument must contain a Hadamard argument for m > 1."));

			final HadamardStatement hStatement = new HadamardStatement(cA, cb);
			final SingleValueProductStatement sStatement = new SingleValueProductStatement(cb, b);

			final Verifiable verifHadamard = hadamardArgumentService.verifyHadamardArgument(hStatement, hArgument)
					.addErrorMessage("Failed to verify Hadamard Argument.");

			final Verifiable verifSVP = singleValueProductArgumentService.verifySingleValueProductArgument(sStatement, sArgument)
					.addErrorMessage("Failed to verify Single Value Product Argument.");

			return verifHadamard.and(verifSVP);
		} else { // corresponds to the case m=1 (number of ciphertexts is prime), where we omit the Hadamard Argument.
			final SingleValueProductStatement sStatement = new SingleValueProductStatement(cA.get(0), b);

			return singleValueProductArgumentService.verifySingleValueProductArgument(sStatement, sArgument)
					.addErrorMessage("Failed to verify Single Value Product Argument.");
		}
	}
}
