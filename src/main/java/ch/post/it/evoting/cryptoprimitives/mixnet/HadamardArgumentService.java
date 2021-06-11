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
import static ch.post.it.evoting.cryptoprimitives.mixnet.Verifiable.create;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import com.google.common.annotations.VisibleForTesting;

import ch.post.it.evoting.cryptoprimitives.ConversionService;
import ch.post.it.evoting.cryptoprimitives.GroupMatrix;
import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableBigInteger;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableString;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

@SuppressWarnings("java:S117")
public class HadamardArgumentService {

	private final RandomService randomService;
	private final HashService hashService;
	private final ElGamalMultiRecipientPublicKey pk;
	private final CommitmentKey ck;
	private final ZeroArgumentService zeroArgumentService;

	/**
	 * Constructs a {code HadamardArgumentService}.
	 * <p>
	 * The inputs must comply with the following:
	 * <ul>
	 *     <li>be non null</li>
	 *     <li>the public key and the commitment key must belong to the same {@link GqGroup}</li>
	 * </ul>
	 *
	 * @param randomService the random service to be used for the creation of random integers.
	 * @param hashService   the hash service that provides the recursive hash function.
	 * @param publicKey     the public key.
	 * @param commitmentKey the commitment key for calculating the commitments.
	 */
	HadamardArgumentService(final RandomService randomService, final HashService hashService, final ElGamalMultiRecipientPublicKey publicKey,
			final CommitmentKey commitmentKey) {
		checkNotNull(randomService);
		checkNotNull(hashService);
		checkNotNull(publicKey);
		checkNotNull(commitmentKey);

		// Check group and dimension of the public and commitment key
		checkArgument(publicKey.getGroup().equals(commitmentKey.getGroup()),
				"The public key and the commitment key must belong to the same group.");

		// Check hash length
		final BigInteger q = publicKey.getGroup().getQ();
		checkArgument(hashService.getHashLength() * Byte.SIZE < q.bitLength(),
				"The hash service's bit length must be smaller than the bit length of q.");

		this.randomService = randomService;
		this.hashService = hashService;
		this.pk = publicKey;
		this.ck = commitmentKey;
		this.zeroArgumentService = new ZeroArgumentService(publicKey, commitmentKey, randomService, hashService);
	}

	/**
	 * Calculates an argument of knowledge of the openings a<sub>0</sub>, ..., a<sub>m-1</sub> and ⃗b to the commitments c<sub>A</sub> and
	 * c<sub>b</sub>.
	 * <p>
	 * The statement and witness must comply with the following:
	 * <ul>
	 *     <li>be non null</li>
	 *     <li>commitment c<sub>A</sub> must have the size as the number of columns in matrix A</li>
	 *     <li>the commitments c<sub>A</sub> must have the same group order than matrix A</li>
	 *     <li>the matrix A must not have more rows than there are elements in the commitment key</li>
	 *     <li>the matrix A must have at least 2 columns</li>
	 *     <li>the commitments c<sub>A</sub> must correspond to the commitments to matrix A</li>
	 *     <li>the vector b must be the Hadamard product of the column vectors of matrix A</li>
	 * </ul>
	 *
	 * @param statement the Hadamard statement.
	 * @param witness   the Hadamard witness.
	 * @return the {@link HadamardArgument} consisting of a vector of commitments and a {@link ZeroArgument}.
	 */
	HadamardArgument getHadamardArgument(final HadamardStatement statement, final HadamardWitness witness) {
		checkNotNull(statement);
		checkNotNull(witness);

		// Extract commitments, matrix, vector and exponents
		final GroupVector<GqElement, GqGroup> c_A = statement.get_c_A();
		final GqElement c_b = statement.get_c_b();
		final GroupMatrix<ZqElement, ZqGroup> A = witness.get_A();
		final GroupVector<ZqElement, ZqGroup> b = witness.get_b();
		final GroupVector<ZqElement, ZqGroup> r = witness.get_r();
		final ZqElement s = witness.get_s();

		// Check dimensions and groups
		final int m = A.numColumns();
		final int n = A.numRows();
		final int nu = ck.size();

		checkArgument(c_A.size() == m, "The commitments for A must have as many elements as matrix A has rows.");
		checkArgument(c_A.getGroup().hasSameOrderAs(A.getGroup()), "The matrix A and its commitments must have the same group order q.");
		checkArgument(n <= nu, "The number of rows in the matrix must be smaller or equal to the commitment key size.");

		// Ensure statement corresponds to witness
		checkArgument(m >= 2, "The matrix must have at least 2 columns.");
		final GroupVector<GqElement, GqGroup> c_A_computed = CommitmentService.getCommitmentMatrix(A, r, ck);
		checkArgument(c_A.equals(c_A_computed),
				"The commitments A must correspond to the commitment to matrix A with exponents r and the given commitment key.");
		final GqElement c_b_computed = CommitmentService.getCommitment(b, s, ck);
		checkArgument(c_b.equals(c_b_computed),
				"The commitment b must correspond to the commitment to vector b with exponent s and the given commitment key.");
		checkArgument(b.equals(getHadamardProduct(A, m - 1)), "The vector b must correspond to the product of the column vectors of the matrix A.");

		// Algorithm
		final ZqGroup zqGroup = A.getGroup();
		final GqGroup gqGroup = c_b.getGroup();
		final BigInteger q = gqGroup.getQ();
		final BigInteger p = gqGroup.getP();

		// Calculate b_0, ..., b_(m-1)
		final GroupVector<GroupVector<ZqElement, ZqGroup>, ZqGroup> b_vectors = IntStream.range(0, m)
				.mapToObj(j -> getHadamardProduct(A, j))
				.collect(toGroupVector());

		// Calculate s_0, ..., s_(m-1)
		final List<ZqElement> s_vector_mutable = new ArrayList<>(m);
		s_vector_mutable.add(0, r.get(0));
		if (m > 2) {
			s_vector_mutable.addAll(1, randomService.genRandomVector(q, m - 2));
		}
		s_vector_mutable.add(m - 1, s);
		final GroupVector<ZqElement, ZqGroup> s_vector = GroupVector.from(s_vector_mutable);

		// Calculate c_(B_0), ..., c_(B_(m-1))
		final List<GqElement> c_B_mutable = new ArrayList<>(m);
		c_B_mutable.add(0, c_A.get(0));
		c_B_mutable.addAll(1, IntStream.range(1, m - 1)
				.mapToObj(j -> CommitmentService.getCommitment(b_vectors.get(j), s_vector.get(j), ck))
				.collect(Collectors.toList()));
		c_B_mutable.add(m - 1, c_b);
		final GroupVector<GqElement, GqGroup> c_B = GroupVector.from(c_B_mutable);

		// Calculate x
		final byte[] x_bytes = hashService.recursiveHash(HashableBigInteger.from(p), HashableBigInteger.from(q), pk, ck, c_A, c_b, c_B);
		final ZqElement x = ZqElement.create(ConversionService.byteArrayToInteger(x_bytes), zqGroup);

		// Calculate y
		final byte[] y_bytes = hashService.recursiveHash(
				HashableString.from("1"),
				HashableBigInteger.from(p),
				HashableBigInteger.from(q),
				pk,
				ck,
				c_A,
				c_b,
				c_B
		);
		final ZqElement y = ZqElement.create(ConversionService.byteArrayToInteger(y_bytes), zqGroup);

		// To avoid computing multiple times the powers of x.
		final GroupVector<ZqElement, ZqGroup> xPowers = IntStream.range(0, m)
				.mapToObj(i -> x.exponentiate(BigInteger.valueOf(i)))
				.collect(toGroupVector());

		// Calculate d_0, ..., d_(m-2)
		final GroupVector<GroupVector<ZqElement, ZqGroup>, ZqGroup> d_matrix = IntStream.range(0, m - 1)
				.mapToObj(i -> b_vectors.get(i).stream()
						.map(element -> xPowers.get(i + 1).multiply(element))
						.collect(toGroupVector()))
				.collect(toGroupVector());

		// Calculate c_(D_0), ..., c_(D_(m-2))
		final GroupVector<GqElement, GqGroup> c_D_vector = IntStream.range(0, m - 1)
				.mapToObj(i -> c_B.get(i).exponentiate(xPowers.get(i + 1)))
				.collect(toGroupVector());

		// Calculate t_0, ..., t_(m-2)
		final GroupVector<ZqElement, ZqGroup> t_vector = IntStream.range(0, m - 1)
				.mapToObj(i -> xPowers.get(i + 1).multiply(s_vector.get(i)))
				.collect(toGroupVector());

		// Calculate d
		final GroupVector<ZqElement, ZqGroup> d = IntStream.range(0, n)
				.mapToObj(j ->
						//Scalar multiplication
						IntStream.range(1, m)
								.mapToObj(i -> xPowers.get(i).multiply(b_vectors.get(i).get(j)))
								//Sum
								.reduce(zqGroup.getIdentity(), ZqElement::add))
				.collect(toGroupVector());

		// Calculate c_D
		final GqElement c_D = IntStream.range(1, m)
				.mapToObj(i -> c_B.get(i).exponentiate(xPowers.get(i)))
				.reduce(gqGroup.getIdentity(), GqElement::multiply);

		// Calculate t
		final ZqElement t = IntStream.range(1, m)
				.mapToObj(i -> xPowers.get(i).multiply(s_vector.get(i)))
				.reduce(zqGroup.getIdentity(), ZqElement::add);

		// (-1, ..., -1) and c_(-1)
		final GroupVector<ZqElement, ZqGroup> minus_one = getMinusOnes(n, zqGroup);
		final ZqElement zero = zqGroup.getIdentity();
		final GqElement c_minus_one = CommitmentService.getCommitment(minus_one, zero, ck);

		// Calculate and return the zero argument.
		// Create statement
		final GroupVector<GqElement, GqGroup> c_A_zero_argument = c_A.subVector(1, m).append(c_minus_one);
		final GroupVector<GqElement, GqGroup> c_D_zero_argument = c_D_vector.append(c_D);
		final ZeroStatement statement_zero_argument = new ZeroStatement(c_A_zero_argument, c_D_zero_argument, y);
		// Create witness
		final GroupMatrix<ZqElement, ZqGroup> a_zero_argument = A.subColumns(1, m).appendColumn(minus_one);
		final GroupMatrix<ZqElement, ZqGroup> d_zero_argument = GroupMatrix.fromColumns(d_matrix).appendColumn(d);
		final GroupVector<ZqElement, ZqGroup> r_zero_argument = r.subVector(1, m).append(zero);
		final GroupVector<ZqElement, ZqGroup> t_zero_argument = t_vector.append(t);
		final ZeroWitness witness_zero_argument = new ZeroWitness(a_zero_argument, d_zero_argument, r_zero_argument, t_zero_argument);
		final ZeroArgument zeroArgument = zeroArgumentService.getZeroArgument(statement_zero_argument, witness_zero_argument);

		return new HadamardArgument(c_B, zeroArgument);
	}

	/**
	 * Verifies the correctness of a {@link HadamardArgument} with respect to a given {@link HadamardStatement}.
	 * <p>
	 * The statement and the argument must be non null and have compatible groups.
	 *
	 * @param statement the statement for which the argument is to be verified.
	 * @param argument  the argument to be verified.
	 * @return a {@link VerificationResult} being valid iff the argument is valid for the given statement.
	 */
	Verifiable verifyHadamardArgument(HadamardStatement statement, HadamardArgument argument) {
		checkNotNull(statement);
		checkNotNull(argument);

		// Retrieve elements for verification
		final GroupVector<GqElement, GqGroup> c_A = statement.get_c_A();
		final GqElement c_b = statement.get_c_b();
		final GroupVector<GqElement, GqGroup> c_B = argument.get_c_B();
		final GroupVector<ZqElement, ZqGroup> a_prime = argument.get_zeroArgument().get_a_prime();

		// Cross-check groups and dimensions
		checkArgument(statement.getGroup().equals(argument.getGroup()),
				"The statement's and the argument's groups must have the same order.");
		checkArgument(statement.get_m() == argument.get_m(), "The statement and the argument must have the same size m.");

		final ZqGroup zqGroup = a_prime.getGroup();
		final GqGroup gqGroup = c_A.getGroup();
		final BigInteger p = gqGroup.getP();
		final BigInteger q = gqGroup.getQ();
		final int m = c_A.size();
		final int n = a_prime.size();

		// Algorithm
		// Calculate x
		final byte[] x_bytes = hashService.recursiveHash(
				HashableBigInteger.from(p),
				HashableBigInteger.from(q),
				pk,
				ck,
				c_A,
				c_b,
				c_B
		);
		final ZqElement x = ZqElement.create(ConversionService.byteArrayToInteger(x_bytes), zqGroup);

		// Calculate y
		final byte[] y_bytes = hashService.recursiveHash(
				HashableString.from("1"),
				HashableBigInteger.from(p),
				HashableBigInteger.from(q),
				pk,
				ck,
				c_A,
				c_b,
				c_B
		);
		final ZqElement y = ZqElement.create(ConversionService.byteArrayToInteger(y_bytes), zqGroup);

		// Pre-calculate the powers of x
		final GroupVector<ZqElement, ZqGroup> xPowers = IntStream.range(0, m)
				.mapToObj(i -> x.exponentiate(BigInteger.valueOf(i)))
				.collect(toGroupVector());

		// Calculate c_(D_0), ..., c_(D_(m-2))
		final GroupVector<GqElement, GqGroup> c_D_vector = IntStream.range(0, m - 1)
				.mapToObj(i -> c_B.get(i).exponentiate(xPowers.get(i + 1)))
				.collect(toGroupVector());

		// Calculate c_D
		final GqElement c_D = IntStream.range(1, m)
				.mapToObj(i -> c_B.get(i).exponentiate(xPowers.get(i)))
				.reduce(gqGroup.getIdentity(), GqElement::multiply);

		// (-1, ..., -1) and c_(-1)
		final GroupVector<ZqElement, ZqGroup> minus_one = getMinusOnes(n, zqGroup);
		final ZqElement zero = zqGroup.getIdentity();
		final GqElement c_minus_1 = CommitmentService.getCommitment(minus_one, zero, ck);

		// Create zero statement
		final GroupVector<GqElement, GqGroup> c_A_zero_argument = c_A.subVector(1, m).append(c_minus_1);
		final GroupVector<GqElement, GqGroup> c_D_zero_argument = c_D_vector.append(c_D);
		final ZeroStatement zeroStatement = new ZeroStatement(c_A_zero_argument, c_D_zero_argument, y);
		final ZeroArgument zeroArgument = argument.get_zeroArgument();

		return create(() -> c_B.get(0).equals(c_A.get(0)), "c_B_0 must equal c_A_0.")
				.and(create(() -> c_B.get(m - 1).equals(c_b), "c_B_m_minus_1 must equal c_b."))
				.and(zeroArgumentService.verifyZeroArgument(zeroStatement, zeroArgument).addErrorMessage("Failed to verify the ZeroArgument."));
	}

	/**
	 * Calculates the Hadamard product for the first <i>bound</i> columns of a matrix.
	 * <p>
	 * The Hadamard product of two column vectors v = (v<sub>0</sub>, ..., v<sub>n-1</sub>) and w = (w<sub>0</sub>, ..., w<sub>n-1</sub> is the entry
	 * wise product vw = (v<sub>0</sub> w<sub>0</sub>, ..., v<sub>n-1</sub> w<sub>n-1</sub>).
	 *
	 * @param matrix A = (a<sub>0</sub>, ..., a<sub>m-1</sub>), the matrix for which to calculate the Hadamard product
	 * @param bound  the index &lt; m of the last column to include in the product
	 * @return &prod;<sub>i=0</sub><sup>j</sup> a<sub>i</sub>
	 */
	@VisibleForTesting
	GroupVector<ZqElement, ZqGroup> getHadamardProduct(final GroupMatrix<ZqElement, ZqGroup> matrix, final int bound) {
		checkNotNull(matrix);
		checkArgument(bound >= 0, "The column index must be greater than or equal to 0.");
		checkArgument(bound < matrix.numColumns(), "The column index must be smaller than the number of rows in the matrix.");

		ZqElement one = ZqElement.create(1, matrix.getGroup());
		final int n = matrix.numRows();
		return IntStream.range(0, n)
				.mapToObj(i -> matrix.getRow(i).stream()
						.limit(bound + 1L)
						.reduce(one, ZqElement::multiply))
				.collect(toGroupVector());
	}

	/**
	 * Creates a {@link GroupVector} with <i>n</i> elements of value <i>q - 1</i>.
	 *
	 * @param size    the size of the vector
	 * @param zqGroup the {@link ZqGroup} of the vector
	 * @return a vector of {@code size} elements with value {@code zqGroup.getQ() - 1}
	 */
	private GroupVector<ZqElement, ZqGroup> getMinusOnes(final int size, final ZqGroup zqGroup) {
		final BigInteger q = zqGroup.getQ();

		return Stream.generate(() -> ZqElement.create(q.subtract(BigInteger.ONE), zqGroup)).limit(size)
				.collect(toGroupVector());
	}
}
