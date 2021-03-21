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
import static ch.post.it.evoting.cryptoprimitives.mixnet.CommitmentService.getCommitmentVector;
import static ch.post.it.evoting.cryptoprimitives.mixnet.Verifiable.create;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import com.google.common.annotations.VisibleForTesting;

import ch.post.it.evoting.cryptoprimitives.ConversionService;
import ch.post.it.evoting.cryptoprimitives.GroupMatrix;
import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.hashing.BoundedHashService;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableBigInteger;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

/**
 * Class in charge of providing a Zero Argument used in the Zero Argument proof.
 */
final class ZeroArgumentService {

	private final ElGamalMultiRecipientPublicKey publicKey;
	private final CommitmentKey commitmentKey;

	private final RandomService randomService;
	private final BoundedHashService hashService;

	ZeroArgumentService(final ElGamalMultiRecipientPublicKey publicKey, final CommitmentKey commitmentKey,
			final RandomService randomService, final BoundedHashService hashService) {

		// Null checking.
		checkNotNull(publicKey);
		checkNotNull(commitmentKey);
		checkNotNull(randomService);
		checkNotNull(hashService);

		// Group checking.
		checkArgument(publicKey.getGroup().equals(commitmentKey.getGroup()), "The public and commitment keys are not from the same group.");

		this.publicKey = publicKey;
		this.commitmentKey = commitmentKey;
		this.randomService = randomService;
		this.hashService = hashService;
	}

	/**
	 * Generates an argument of knowledge of the values <code>a<sub>1</sub>, b<sub>0</sub>, ..., a<sub>m</sub>, b<sub>m-1</sub></code> such that
	 * &sum;<sub>i=1</sub><sup>m</sup> a<sub>i</sub> &#8902; b<sub>i-1</sub> = 0. The statement and witness must comply with the following:
	 * <ul>
	 *  <li>be non null</li>
	 *  <li>commitments must have the same size as the exponents</li>
	 *  <li>y must be part of the same group as the exponents elements</li>
	 *  <li>c<sub>A</sub> = getCommitmentMatrix(A, r, commitmentKey)</li>
	 *  <li>c<sub>B</sub> = getCommitmentMatrix(B, s, commitmentKey)</li>
	 *  <li>&sum;<sub>i=1</sub><sup>m</sup> a<sub>i</sub> &#8902; b<sub>i-1</sub> = 0</li>
	 * </ul>
	 *
	 * @param statement The zero argument statement.
	 * @param witness   The zero argument witness.
	 * @return The argument of knowledge as a {@link ZeroArgument}.
	 */
	ZeroArgument getZeroArgument(final ZeroStatement statement, final ZeroWitness witness) {
		// Null checking.
		checkNotNull(statement);
		checkNotNull(witness);

		final GroupMatrix<ZqElement, ZqGroup> matrixA = witness.getMatrixA();
		final GroupMatrix<ZqElement, ZqGroup> matrixB = witness.getMatrixB();
		final GroupVector<ZqElement, ZqGroup> exponentsR = witness.getExponentsR();
		final GroupVector<ZqElement, ZqGroup> exponentsS = witness.getExponentsS();
		final GroupVector<GqElement, GqGroup> commitmentsA = statement.getCommitmentsA();
		final GroupVector<GqElement, GqGroup> commitmentsB = statement.getCommitmentsB();
		final ZqElement y = statement.getY();

		// Cross dimensions checking between statement and witness.
		checkArgument(commitmentsA.size() == exponentsR.size(), "The statement commitments must have the same size as the witness exponents.");

		// Cross group checking.
		checkArgument(y.getGroup().equals(exponentsR.getGroup()), "The statement y and witness exponents must be part of the same group.");

		// Ensure the statement and witness are corresponding.
		final GroupVector<GqElement, GqGroup> computedCommitmentsA = getCommitmentMatrix(matrixA, exponentsR, commitmentKey);
		checkArgument(commitmentsA.equals(computedCommitmentsA), "The statement's Ca commitments must be equal to the witness' commitment matrix A.");
		final GroupVector<GqElement, GqGroup> computedCommitmentsB = getCommitmentMatrix(matrixB, exponentsS, commitmentKey);
		checkArgument(commitmentsB.equals(computedCommitmentsB), "The statement's Cb commitments must be equal to the witness' commitment matrix B.");

		final ZqGroup zqGroup = y.getGroup();

		// The specifications uses the indices [1,m] for matrixA and [0,m-1] for matrixB. In the code, we use [0,m-1] for both indices.
		final int m = matrixA.numColumns();
		final ZqElement starMapSum = IntStream.range(0, m)
				.mapToObj(i -> starMap(matrixA.getColumn(i), matrixB.getColumn(i), y))
				.reduce(zqGroup.getIdentity(), ZqElement::add);
		checkArgument(zqGroup.getIdentity().equals(starMapSum),
				"The sum of the starMap operations between the witness's matrices columns is not equal to 0.");

		// Algorithm operations.

		final int n = matrixA.numRows();
		final BigInteger q = zqGroup.getQ();
		final GroupVector<ZqElement, ZqGroup> a0 = randomService.genRandomVector(q, n);
		final GroupVector<ZqElement, ZqGroup> bm = randomService.genRandomVector(q, n);
		final ZqElement r0 = ZqElement.create(randomService.genRandomInteger(q), zqGroup);
		final ZqElement sm = ZqElement.create(randomService.genRandomInteger(q), zqGroup);
		final GqElement cA0 = getCommitment(a0, r0, commitmentKey);
		final GqElement cBm = getCommitment(bm, sm, commitmentKey);

		// Compute the D vector.
		final GroupMatrix<ZqElement, ZqGroup> augmentedMatrixA = matrixA.prependColumn(a0);
		final GroupMatrix<ZqElement, ZqGroup> augmentedMatrixB = matrixB.appendColumn(bm);

		final GroupVector<ZqElement, ZqGroup> d = computeDVector(augmentedMatrixA, augmentedMatrixB, y);

		// Compute t and c_d.
		final List<ZqElement> t = new ArrayList<>(randomService.genRandomVector(q, (2 * m) + 1));
		t.set(m + 1, ZqElement.create(BigInteger.ZERO, zqGroup));
		final GroupVector<GqElement, GqGroup> cd = getCommitmentVector(d, GroupVector.from(t), commitmentKey);

		// Compute x, later used to compute a', b', r', s' and t'.
		final byte[] hash = getHash(commitmentsA, commitmentsB, cA0, cBm, cd);
		final ZqElement x = ZqElement.create(ConversionService.byteArrayToInteger(hash), zqGroup);

		// To avoid computing multiple times the powers of x.
		final List<ZqElement> xExpI = IntStream.range(0, 2 * m + 1)
				.mapToObj(i -> x.exponentiate(BigInteger.valueOf(i)))
				.collect(Collectors.toCollection(ArrayList::new));

		// Compute vectors a' and b'.
		final GroupVector<ZqElement, ZqGroup> aPrime = IntStream.range(0, n)
				.mapToObj(j ->
						IntStream.range(0, m + 1)
								.mapToObj(i -> xExpI.get(i).multiply(augmentedMatrixA.get(j, i)))
								.reduce(zqGroup.getIdentity(), ZqElement::add))
				.collect(toGroupVector());

		final GroupVector<ZqElement, ZqGroup> bPrime = IntStream.range(0, n)
				.mapToObj(j ->
						IntStream.range(0, m + 1)
								.mapToObj(i -> xExpI.get(m - i).multiply(augmentedMatrixB.get(j, i)))
								.reduce(zqGroup.getIdentity(), ZqElement::add))
				.collect(toGroupVector());

		// Compute r', s' and t'.
		final GroupVector<ZqElement, ZqGroup> augmentedExponentsR = exponentsR.prepend(r0);
		final GroupVector<ZqElement, ZqGroup> augmentedExponentsS = exponentsS.append(sm);

		final ZqElement rPrime = IntStream.range(0, m + 1)
				.mapToObj(i -> xExpI.get(i).multiply(augmentedExponentsR.get(i)))
				.reduce(zqGroup.getIdentity(), ZqElement::add);

		final ZqElement sPrime = IntStream.range(0, m + 1)
				.mapToObj(i -> xExpI.get(m - i).multiply(augmentedExponentsS.get(i)))
				.reduce(zqGroup.getIdentity(), ZqElement::add);

		final ZqElement tPrime = IntStream.range(0, 2 * m + 1)
				.mapToObj(i -> xExpI.get(i).multiply(t.get(i)))
				.reduce(zqGroup.getIdentity(), ZqElement::add);

		// Construct the ZeroArgument with all computed parameters.
		final ZeroArgument.Builder zeroArgumentBuilder = new ZeroArgument.Builder();
		zeroArgumentBuilder
				.withCA0(cA0)
				.withCBm(cBm)
				.withCd(cd)
				.withAPrime(aPrime)
				.withBPrime(bPrime)
				.withRPrime(rPrime)
				.withSPrime(sPrime)
				.withTPrime(tPrime);

		return zeroArgumentBuilder.build();
	}

	/**
	 * Computes the vector <b>d</b> for the GetZeroArgument algorithm. The input matrices must comply with the following:
	 * <ul>
	 *     <li>be non null</li>
	 *     <li>each matrix row must have the same number of columns</li>
	 *     <li>both matrices must have the same number of lines and columns</li>
	 *     <li>all matrix elements must be part of the same group as the value y</li>
	 * </ul>
	 *
	 * @param firstMatrix  A, the first matrix.
	 * @param secondMatrix B, the second matrix.
	 * @return the computed <b>d</b> vector.
	 */
	@VisibleForTesting
	GroupVector<ZqElement, ZqGroup> computeDVector(final GroupMatrix<ZqElement, ZqGroup> firstMatrix,
			final GroupMatrix<ZqElement, ZqGroup> secondMatrix, final ZqElement y) {

		// Null checking.
		checkNotNull(firstMatrix);
		checkNotNull(secondMatrix);
		checkNotNull(y);

		// Cross matrix dimensions checking.
		checkArgument(firstMatrix.numRows() == secondMatrix.numRows(), "The two matrices must have the same number of rows.");
		checkArgument(firstMatrix.numColumns() == secondMatrix.numColumns(), "The two matrices must have the same number of columns.");

		if (firstMatrix.isEmpty()) {
			return GroupVector.of();
		}

		// Cross matrix group checking.
		checkArgument(firstMatrix.getGroup().equals(secondMatrix.getGroup()), "The elements of both matrices must be in the same group.");
		checkArgument(y.getGroup().equals(firstMatrix.getGroup()), "The value y must be in the same group as the elements of the matrices.");

		// Computing the d vector.
		final int m = firstMatrix.numColumns() - 1;
		final LinkedList<ZqElement> d = new LinkedList<>();
		final ZqGroup group = y.getGroup();
		for (int k = 0; k <= 2 * m; k++) {
			ZqElement dk = group.getIdentity();
			for (int i = Math.max(0, k - m); i <= m; i++) {
				final int j = (m - k) + i;
				if (j > m) {
					break;
				}
				dk = dk.add(starMap(firstMatrix.getColumn(i), secondMatrix.getColumn(j), y));
			}
			d.add(dk);
		}

		return GroupVector.from(d);
	}

	/**
	 * Defines the bilinear map represented by the star operator &#8902; in the specification. All elements must be in the same group. The algorithm
	 * defined by the value {@code y} is the following:
	 * <p>
	 * (a<sub>0</sub>,..., a<sub>n-1</sub>) &#8902; (b<sub>0</sub>,...,b<sub>n-1</sub>) = &sum;<sub>j=0</sub><sup>n-1</sup> a<sub>j</sub> &middot;
	 * b<sub>j</sub> &middot; y<sup>j</sup>
	 *
	 * @param firstVector  a, the first vector.
	 * @param secondVector b, the second vector.
	 * @return The sum &sum;<sub>j=0</sub><sup>n-1</sup> a<sub>j</sub> &middot; b<sub>j</sub> &middot; y<sup>j</sup>
	 */
	@VisibleForTesting
	ZqElement starMap(final GroupVector<ZqElement, ZqGroup> firstVector, final GroupVector<ZqElement, ZqGroup> secondVector,
			final ZqElement y) {

		// Null checking.
		checkNotNull(firstVector);
		checkNotNull(secondVector);
		checkNotNull(y);

		// Cross dimensions checking.
		checkArgument(firstVector.size() == secondVector.size(), "The provided vectors must have the same size.");

		// Handle empty vectors.
		if (firstVector.isEmpty()) {
			return y.getGroup().getIdentity();
		}

		// Cross group checking.
		checkArgument(firstVector.getGroup().equals(secondVector.getGroup()), "The elements of both vectors must be in the same group.");
		checkArgument(firstVector.getGroup().equals(y.getGroup()), "The value y must be in the same group as the vectors elements");
		final ZqGroup group = y.getGroup();

		// StarMap computing.
		final int n = firstVector.size();
		return IntStream.range(0, n)
				.mapToObj(j -> firstVector.get(j)
						.multiply(secondVector.get(j))
						.multiply(y.exponentiate(BigInteger.valueOf(j + 1L))))
				.reduce(group.getIdentity(), ZqElement::add);
	}

	/**
	 * Verifies the correctness of a {@link ZeroArgument} with respect to a given {@link ZeroStatement}.
	 * <p>
	 * The statement and the argument must be non null and have compatible groups.
	 *
	 * @param argument  the statement for which the argument is to be verified.
	 * @param statement the argument to be verified.
	 * @return a {@link VerificationResult} being valid iff the argument is valid for the given statement.
	 */
	Verifiable verifyZeroArgument(final ZeroStatement statement, final ZeroArgument argument) {

		checkNotNull(statement);
		checkNotNull(argument);
		checkArgument(statement.getCommitmentsA().getGroup().equals(argument.getCd().getGroup()),
				"Statement and argument do not share the same group");

		final GroupVector<GqElement, GqGroup> cA = statement.getCommitmentsA();
		final GroupVector<GqElement, GqGroup> cd = argument.getCd();
		final GroupVector<GqElement, GqGroup> cB = statement.getCommitmentsB();

		final int m = cA.size();
		checkArgument((cd.size() - 2 * m) == 1, "The m of the statement should be equal to the m of the argument (2m+1)");

		final ZqElement x = hashAndConvertX(statement, argument);

		final Verifiable verifCd = create(() -> BigInteger.ONE.equals(cd.get(m + 1).getValue()),
				String.format("cd.get(m + 1).getValue() %s should equal BigInteger.ONE", cd.get(m + 1).getValue()));

		final List<ZqElement> exponentiatedXs = IntStream.range(0, (2 * m) + 1)
				.mapToObj(i -> x.exponentiate(BigInteger.valueOf(i)))
				.collect(Collectors.toList());

		final GqElement identity = cA.getGroup().getIdentity();

		final GroupVector<GqElement, GqGroup> augmentedCA = cA.prepend(argument.getCA0());

		final GqElement prodCa = IntStream.range(0, m + 1)
				.mapToObj(i -> augmentedCA.get(i).exponentiate(exponentiatedXs.get(i)))
				.reduce(identity, GqElement::multiply);

		final GroupVector<ZqElement, ZqGroup> aPrime = argument.getAPrime();
		final ZqElement rPrime = argument.getRPrime();

		final GqElement commA = getCommitment(aPrime, rPrime, commitmentKey);
		final Verifiable verifA = create(() -> prodCa.equals(commA), String.format("commA %s and prodCa %s are not equal", commA, prodCa));

		final GroupVector<GqElement, GqGroup> augmentedCB = cB.append(argument.getCBm());

		final GqElement prodCb = IntStream.range(0, m + 1)
				.mapToObj(i -> augmentedCB.get(m - i).exponentiate(exponentiatedXs.get(i)))
				.reduce(identity, GqElement::multiply);

		final GroupVector<ZqElement, ZqGroup> bPrime = argument.getBPrime();
		final ZqElement sPrime = argument.getSPrime();

		final GqElement commB = getCommitment(bPrime, sPrime, commitmentKey);
		final Verifiable verifB = create(() -> prodCb.equals(commB), String.format("prodCb %s and commB %s are not equal", prodCb, commB));

		final GqElement prodCd = IntStream.range(0, (2 * m) + 1)
				.mapToObj(i -> cd.get(i).exponentiate(exponentiatedXs.get(i)))
				.reduce(identity, GqElement::multiply);

		final GroupVector<ZqElement, ZqGroup> prod = GroupVector.of(starMap(aPrime, bPrime, statement.getY()));

		final ZqElement tPrime = argument.getTPrime();
		final GqElement commD = getCommitment(prod, tPrime, commitmentKey);
		final Verifiable verifD = create(() -> prodCd.equals(commD), String.format("prodCd %s and commD %s are not equal", prodCd, commD));

		return verifCd.and(verifA).and(verifB).and(verifD);
	}

	private ZqElement hashAndConvertX(final ZeroStatement zeroStatement, final ZeroArgument zeroArgument) {
		final GroupVector<GqElement, GqGroup> cA = zeroStatement.getCommitmentsA();
		final GroupVector<GqElement, GqGroup> cB = zeroStatement.getCommitmentsB();
		final GqGroup group = cA.getGroup();

		final GqElement cA0 = zeroArgument.getCA0();
		final GqElement cBm = zeroArgument.getCBm();

		final GroupVector<GqElement, GqGroup> cd = zeroArgument.getCd();

		final byte[] hash = getHash(cA, cB, cA0, cBm, cd);
		return ZqElement.create(ConversionService.byteArrayToInteger(hash), ZqGroup.sameOrderAs(group));
	}

	private byte[] getHash(final GroupVector<GqElement, GqGroup> commitmentsA, final GroupVector<GqElement, GqGroup> commitmentsB,
			final GqElement cA0, final GqElement cBm, final GroupVector<GqElement, GqGroup> cd) {

		final GqGroup gqGroup = commitmentsA.get(0).getGroup();
		final BigInteger p = gqGroup.getP();
		final BigInteger q = gqGroup.getQ();

		return hashService.recursiveHash(
				HashableBigInteger.from(p),
				HashableBigInteger.from(q),
				publicKey,
				commitmentKey,
				cA0,
				cBm,
				cd,
				commitmentsB,
				commitmentsA
		);
	}

}
