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
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BooleanSupplier;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.ConversionService;
import ch.post.it.evoting.cryptoprimitives.GroupMatrix;
import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.HashableBigInteger;
import ch.post.it.evoting.cryptoprimitives.HashableString;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

public class HadamardArgumentService {

	private final RandomService randomService;
	private final MixnetHashService hashService;
	private final ElGamalMultiRecipientPublicKey publicKey;
	private final CommitmentKey commitmentKey;
	private final ZeroArgumentService zeroArgumentService;

	private final Logger log = LoggerFactory.getLogger(HadamardArgumentService.class);

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
	HadamardArgumentService(final RandomService randomService, final MixnetHashService hashService, final ElGamalMultiRecipientPublicKey publicKey,
			final CommitmentKey commitmentKey) {
		checkNotNull(randomService);
		checkNotNull(hashService);
		checkNotNull(publicKey);
		checkNotNull(commitmentKey);

		// Check group and dimension of the public and commitment key
		checkArgument(publicKey.getGroup().equals(commitmentKey.getGroup()),
				"The public key and the commitment key must belong to the same group.");

		this.randomService = randomService;
		this.hashService = hashService;
		this.publicKey = publicKey;
		this.commitmentKey = commitmentKey;
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
	 *     <li>the matrix A must not have more columns than there are elements in the commitment key</li>
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
		final GroupVector<GqElement, GqGroup> cA = statement.getCommitmentsA();
		final GqElement cb = statement.getCommitmentB();
		@SuppressWarnings("squid:S00117")
		final GroupMatrix<ZqElement, ZqGroup> A = witness.getMatrixA();
		final GroupVector<ZqElement, ZqGroup> b = witness.getVectorB();
		final GroupVector<ZqElement, ZqGroup> r = witness.getExponentsR();
		final ZqElement s = witness.getExponentS();

		// Check dimensions and groups
		final int m = A.numColumns();
		final int n = A.numRows();
		final int k = commitmentKey.size();
		checkArgument(cA.size() == m, "The commitments for A must have as many elements as matrix A has rows.");
		checkArgument(cA.getGroup().hasSameOrderAs(A.getGroup()), "The matrix A and its commitments must have the same group order q.");
		checkArgument(n <= k, "The number of rows in the matrix must be smaller than the commitment key size.");

		// Ensure statement corresponds to witness
		checkArgument(m >= 2, "The matrix must have at least 2 columns.");
		final GroupVector<GqElement, GqGroup> commitments = CommitmentService.getCommitmentMatrix(A, r, commitmentKey);
		checkArgument(cA.equals(commitments),
				"The commitments A must correspond to the commitment to matrix A with exponents r and the given commitment key.");
		final GqElement commitment = CommitmentService.getCommitment(b, s, commitmentKey);
		checkArgument(cb.equals(commitment),
				"The commitment b must correspond to the commitment to vector b with exponent s and the given commitment key.");
		checkArgument(b.equals(getHadamardProduct(A, A.numColumns() - 1)),
				"The vector b must correspond to the product of the column vectors of the matrix A.");

		// Start operation
		final ZqGroup zqGroup = A.getGroup();
		final GqGroup gqGroup = cb.getGroup();
		final BigInteger q = gqGroup.getQ();
		final BigInteger p = gqGroup.getP();

		// Calculate b_0, ..., b_(m-1)
		final List<GroupVector<ZqElement, ZqGroup>> bList = IntStream.range(0, m)
				.mapToObj(j -> getHadamardProduct(A, j))
				.collect(Collectors.toList());

		// Calculate s_0, ..., s_(m-1)
		final List<ZqElement> sElements = new ArrayList<>(m);
		sElements.add(0, r.get(0));
		if (m > 2) {
			sElements.addAll(1, randomService.genRandomVector(q, m - 2));
		}
		sElements.add(m - 1, s);
		ImmutableList<ZqElement> sList = ImmutableList.copyOf(sElements);

		// Calculate c_(B_0), ..., c_(B_(m-1))
		final List<GqElement> cBList = new ArrayList<>(m);
		cBList.add(0, cA.get(0));
		cBList.addAll(1, IntStream.range(1, m - 1)
				.mapToObj(j -> CommitmentService.getCommitment(bList.get(j), sList.get(j), commitmentKey))
				.collect(Collectors.toList()));
		cBList.add(m - 1, cb);
		final GroupVector<GqElement, GqGroup> cBVector = GroupVector.from(cBList);

		// Calculate x
		final byte[] hashX = hashService.recursiveHash(
				HashableBigInteger.from(p),
				HashableBigInteger.from(q),
				publicKey,
				commitmentKey,
				cA,
				cb,
				cBVector
		);
		final ZqElement x = ZqElement.create(ConversionService.byteArrayToInteger(hashX), zqGroup);

		// Calculate y
		final byte[] hashY = hashService.recursiveHash(
				HashableString.from("1"),
				HashableBigInteger.from(p),
				HashableBigInteger.from(q),
				publicKey,
				commitmentKey,
				cA,
				cb,
				cBVector
		);
		final ZqElement y = ZqElement.create(ConversionService.byteArrayToInteger(hashY), zqGroup);

		// To avoid computing multiple times the powers of x.
		final List<ZqElement> xExpI = IntStream.range(0, m)
				.mapToObj(i -> x.exponentiate(BigInteger.valueOf(i)))
				.collect(Collectors.toCollection(ArrayList::new));

		// Calculate d_0, ..., d_(m-2)
		final List<List<ZqElement>> diList = IntStream.range(0, m - 1)
				.mapToObj(i -> bList.get(i).stream()
						.map(element -> xExpI.get(i + 1).multiply(element))
						.collect(Collectors.toList()))
				.collect(Collectors.toList());

		// Calculate c_(D_0), ..., c_(D_(m-2))
		final GroupVector<GqElement, GqGroup> cDiList = IntStream.range(0, m - 1)
				.mapToObj(i -> cBVector.get(i).exponentiate(xExpI.get(i + 1)))
				.collect(toGroupVector());

		// Calculate t_0, ..., t_(m-2)
		final GroupVector<ZqElement, ZqGroup> tiList = IntStream.range(0, m - 1)
				.mapToObj(i -> xExpI.get(i + 1).multiply(sList.get(i)))
				.collect(toGroupVector());

		// Calculate d
		final GroupVector<ZqElement, ZqGroup> dElements = IntStream.range(0, n)
				.mapToObj(i -> IntStream.range(1, m)
						.mapToObj(j -> xExpI.get(j).multiply(bList.get(j).get(i)))
						.reduce(zqGroup.getIdentity(), ZqElement::add))
				.collect(toGroupVector());

		// Calculate c_D
		final GqElement cD = IntStream.range(1, m)
				.mapToObj(i -> cBVector.get(i).exponentiate(xExpI.get(i)))
				.reduce(gqGroup.getIdentity(), GqElement::multiply);

		// Calculate t
		final ZqElement t = IntStream.range(1, m)
				.mapToObj(i -> xExpI.get(i).multiply(sList.get(i)))
				.reduce(zqGroup.getIdentity(), ZqElement::add);

		// (-1, ..., -1) and c_(-1)
		final GroupVector<ZqElement, ZqGroup> minusOnes = getMinusOnes(n, zqGroup);
		final ZqElement zero = zqGroup.getIdentity();
		final GqElement cMinusOne = CommitmentService.getCommitment(minusOnes, zero, commitmentKey);

		// Calculate and return the zero argument.
		// Beware that we name the variables as they are called within the zero argument (and not how they are called in the Hadamard argument).
		// Therefore, D becomes B and T becomes S.
		// Create statement
		final GroupVector<GqElement, GqGroup> zCommitmentsA = cA.append(cMinusOne).stream().skip(1)
				.collect(toGroupVector());
		final GroupVector<GqElement, GqGroup> zCommitmentsB = cDiList.append(cD);
		ZeroStatement zStatement = new ZeroStatement(zCommitmentsA, zCommitmentsB, y);
		// Create witness
		final GroupMatrix<ZqElement, ZqGroup> zMatrixA = GroupMatrix
				.fromColumns(A.appendColumn(minusOnes).columnStream().skip(1).map(ArrayList::new)
						.collect(Collectors.toList()));
		final GroupMatrix<ZqElement, ZqGroup> zMatrixB = GroupMatrix.fromColumns(diList).appendColumn(dElements);
		final GroupVector<ZqElement, ZqGroup> zExponentsR = r.append(zero).stream().skip(1)
				.collect(toGroupVector());
		final GroupVector<ZqElement, ZqGroup> zExponentsS = tiList.append(t);
		ZeroWitness zWitness = new ZeroWitness(zMatrixA, zMatrixB, zExponentsR, zExponentsS);

		// Prepare Hadamard argument
		GroupVector<GqElement, GqGroup> cB = GroupVector.from(cBList);
		ZeroArgument zeroArgument = zeroArgumentService.getZeroArgument(zStatement, zWitness);

		return new HadamardArgument(cB, zeroArgument);
	}

	/**
	 * Verifies the correctness of a {@link HadamardArgument} with respect to a given {@link HadamardStatement}.
	 * <p>
	 * The statement and the argument must be non null and have compatible groups.
	 *
	 * @param statement the statement for which the argument is to be verified.
	 * @param argument  the argument to be verified.
	 * @return <b>true</b> if the argument is valid for the given statement, <b>false</b> otherwise
	 */
	boolean verifyHadamardArgument(HadamardStatement statement, HadamardArgument argument) {
		checkNotNull(statement);
		checkNotNull(argument);

		// Retrieve elements for verification
		final GroupVector<GqElement, GqGroup> cA = statement.getCommitmentsA();
		final GqElement cLowerB = statement.getCommitmentB();
		final GroupVector<GqElement, GqGroup> cUpperB = argument.getCommitmentsB();
		final GroupVector<ZqElement, ZqGroup> aPrime = argument.getZeroArgument().getAPrime();

		// Cross-check groups and dimensions
		checkArgument(statement.getGroup().equals(argument.getGroup()),
				"The statement's and the argument's groups must have the same order.");
		checkArgument(statement.getM() == argument.getM(), "The statement and the argument must have the same size m.");

		final ZqGroup zqGroup = aPrime.getGroup();
		final GqGroup gqGroup = cA.getGroup();
		final BigInteger p = cA.getGroup().getP();
		final BigInteger q = cA.getGroup().getQ();

		// Start verification
		final int m = cA.size();
		final BooleanSupplier verifB = () -> cUpperB.get(0).equals(cA.get(0)) && cUpperB.get(m - 1).equals(cLowerB);
		if (!verifB.getAsBoolean()) {
			log.error("cUpperB.get(0) {} must equal cA.get(0) {} and cUpperB.get(m - 1) {} must equal cLowerB {}",
					cUpperB.get(0), cA.get(0), cUpperB.get(m - 1), cLowerB);
			return false;
		}

		// Calculate x
		final byte[] hashX = hashService.recursiveHash(
				HashableBigInteger.from(p),
				HashableBigInteger.from(q),
				publicKey,
				commitmentKey,
				cA,
				cLowerB,
				cUpperB
		);
		final ZqElement x = ZqElement.create(ConversionService.byteArrayToInteger(hashX), zqGroup);

		// Calculate y
		final byte[] hashY = hashService.recursiveHash(
				HashableString.from("1"),
				HashableBigInteger.from(p),
				HashableBigInteger.from(q),
				publicKey,
				commitmentKey,
				cA,
				cLowerB,
				cUpperB
		);
		final ZqElement y = ZqElement.create(ConversionService.byteArrayToInteger(hashY), zqGroup);

		// Pre-calculate the powers of x
		final GroupVector<ZqElement, ZqGroup> xPowers = IntStream.range(0, m)
				.mapToObj(i -> x.exponentiate(BigInteger.valueOf(i)))
				.collect(toGroupVector());

		// Calculate c_(D_0), ..., c_(D_(m-2))
		final GroupVector<GqElement, GqGroup> cDiList = IntStream.range(0, m - 1)
				.mapToObj(i -> cUpperB.get(i).exponentiate(xPowers.get(i + 1)))
				.collect(toGroupVector());

		// Calculate c_D
		final GqElement cD = IntStream.range(1, m)
				.mapToObj(i -> cUpperB.get(i).exponentiate(xPowers.get(i)))
				.reduce(gqGroup.getIdentity(), GqElement::multiply);

		// (-1, ..., -1) and c_(-1)
		final int n = aPrime.size();
		final GroupVector<ZqElement, ZqGroup> minusOnes = getMinusOnes(n, zqGroup);
		final ZqElement zero = zqGroup.getIdentity();
		final GqElement cMinusOne = CommitmentService.getCommitment(minusOnes, zero, commitmentKey);

		// Create zero statement
		final GroupVector<GqElement, GqGroup> zCommitmentsA = cA.append(cMinusOne).stream().skip(1).collect(toGroupVector());
		final GroupVector<GqElement, GqGroup> zCommitmentsB = cDiList.append(cD);
		final ZeroStatement zStatement = new ZeroStatement(zCommitmentsA, zCommitmentsB, y);
		final ZeroArgument zArgument = argument.getZeroArgument();
		final BooleanSupplier verifZ = () -> zeroArgumentService.verifyZeroArgument(zStatement, zArgument);

		if (!verifZ.getAsBoolean()) {
			log.error("Failed to verify the ZeroArgument");
			return false;
		}

		return verifB.getAsBoolean() && verifZ.getAsBoolean();
	}

	/**
	 * Calculates the Hadamard product for the first <i>j - 1</i> column vectors of a matrix.
	 * <p>
	 * The Hadamard product of two column vectors v = (v<sub>0</sub>, ..., v<sub>n-1</sub>) and w = (w<sub>0</sub>, ..., w<sub>n-1</sub> is the entry
	 * wise product vw = (v<sub>0</sub> w<sub>0</sub>, ..., v<sub>n-1</sub> w<sub>n-1</sub>).
	 *
	 * @param matrix A = (a<sub>0</sub>, ..., a<sub>m-1</sub>), the matrix for which to calculate the Hadamard product
	 * @param j      the index &le; m-1 of the last column to include in the product
	 * @return &prod;<sub>i=0</sub><sup>j</sup> a<sub>i</sub>
	 */
	GroupVector<ZqElement, ZqGroup> getHadamardProduct(final GroupMatrix<ZqElement, ZqGroup> matrix, final int j) {
		checkNotNull(matrix);
		checkArgument(j >= 0, "The column index must be greater than or equal to 0.");
		checkArgument(j < matrix.numColumns(), "The column index must be smaller than the number of rows in the matrix.");
		ZqElement one = ZqElement.create(1, matrix.getGroup());
		int n = matrix.numRows();
		return IntStream.range(0, n)
				.mapToObj(i -> matrix.getRow(i).stream()
						.limit(j + 1L)
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
		BigInteger q = zqGroup.getQ();

		return Stream.generate(() -> ZqElement.create(q.subtract(BigInteger.ONE), zqGroup)).limit(size)
				.collect(toGroupVector());
	}
}
