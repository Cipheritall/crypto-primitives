package ch.post.it.evoting.cryptoprimitives.mixnet;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import ch.post.it.evoting.cryptoprimitives.SameGroupMatrix;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;

public class ZeroArgumentTestData {

	private static final int RANDOM_UPPER_BOUND = 10;
	private static final SecureRandom secureRandom = new SecureRandom();

	private final ZqGroupGenerator zqGroupGenerator;
	private final GqGroupGenerator gqGroupGenerator;
	private final ZeroArgumentService zeroArgumentService;
	private final RandomService randomService = new RandomService();

	private ZeroStatement zeroStatement;
	private ZeroWitness zeroWitness;

	private int m;
	private int n;

	public ZeroArgumentTestData(CommitmentKey commitmentKey,
			ZeroArgumentService zeroArgumentService) {

		GqGroup gqGroup = commitmentKey.getGroup();
		ZqGroup zqGroup = ZqGroup.sameOrderAs(gqGroup);
		zqGroupGenerator = new ZqGroupGenerator(zqGroup);
		gqGroupGenerator = new GqGroupGenerator(gqGroup);
		this.zeroArgumentService = zeroArgumentService;
		genRandomStatementAndWitness(zqGroup, commitmentKey);
	}

	private void genRandomStatementAndWitness(ZqGroup zqGroup, CommitmentKey commitmentKey) {
		// Columns.
		m = secureRandom.nextInt(RANDOM_UPPER_BOUND) + 1;
		// Rows.
		n = secureRandom.nextInt(RANDOM_UPPER_BOUND) + 1;

		// Construct valid witness and statement so that the zero product property holds. To do so, pick at random every witness parameters and
		// the witness' y value. Then isolate the last element of matrix B, B_(n,m) in the expanded zero product property. Once done, try every
		// member of the Zq group as a value for B_(n,m) until the zero product property is satisfied. This is fast as long as the test groups are
		// small.
		SameGroupVector<ZqElement, ZqGroup> exponentsR = zqGroupGenerator.generateRandomZqElementVector(m);
		SameGroupVector<ZqElement, ZqGroup> exponentsS = zqGroupGenerator.generateRandomZqElementVector(m);

		// Generate a new set of random values until a valid B_(n,m) is found.
		Optional<ZqElement> matrixBLastElem;
		ZqElement y;
		SameGroupMatrix<ZqElement, ZqGroup> matrixA;
		SameGroupMatrix<ZqElement, ZqGroup> matrixB;
		do {
			matrixA = zqGroupGenerator.generateRandomZqElementMatrix(n, m);
			matrixB = zqGroupGenerator.generateRandomZqElementMatrix(n, m);

			y = ZqElement.create(randomService.genRandomInteger(zqGroup.getQ()), zqGroup);

			// Copies to be usable in streams.
			final SameGroupMatrix<ZqElement, ZqGroup> finalMatrixA = matrixA;
			final SameGroupMatrix<ZqElement, ZqGroup> finalMatrixB = matrixB;
			ZqElement finalY = y;

			final ZqElement sumOfOtherZeroProductTerms = IntStream.range(0, m - 1)
					.mapToObj(
							i -> zeroArgumentService.starMap(
									finalMatrixA.getColumn(i),
									finalMatrixB.getColumn(i),
									finalY))
					.reduce(zqGroup.getIdentity(), ZqElement::add).negate();
			// Corresponds to starMap with last column of matrices, without its last element.
			final ZqElement sumOfOtherStarMapTerms = IntStream.range(0, n - 1)
					.mapToObj(j -> finalMatrixA.get(j, m - 1)
							.multiply(finalMatrixB.get(j, m - 1))
							.multiply(finalY.exponentiate(BigInteger.valueOf(j + 1L))))
					.reduce(zqGroup.getIdentity(), ZqElement::add).negate();
			final ZqElement otherTerms = sumOfOtherZeroProductTerms.add(sumOfOtherStarMapTerms);

			matrixBLastElem = IntStream.range(0, zqGroup.getQ().intValue())
					.mapToObj(i -> ZqElement.create(BigInteger.valueOf(i), zqGroup))
					.filter(candidate -> finalMatrixA.get(n - 1, m - 1)
							.multiply(candidate)
							.multiply(finalY.exponentiate(BigInteger.valueOf(n)))
							.equals(otherTerms))
					.findAny();
		} while (!matrixBLastElem.isPresent());

		// Replace B_(n,m) by the value satisfying the ensure equation.
		final List<List<ZqElement>> rows = matrixB.rowStream()
				.map(sgv -> sgv.stream().collect(Collectors.toList()))
				.collect(Collectors.toCollection(ArrayList::new));
		final List<ZqElement> lastRow = matrixB.getRow(n - 1).stream().collect(Collectors.toCollection(ArrayList::new));
		lastRow.set(m - 1, matrixBLastElem.get());
		rows.set(n - 1, lastRow);
		SameGroupMatrix<ZqElement, ZqGroup> updatedMatrixB = SameGroupMatrix.fromRows(rows);

		// Construct the remaining parts of the statement.
		SameGroupVector<GqElement, GqGroup> commitmentsCa = CommitmentService
				.getCommitmentMatrix(matrixA, exponentsR, commitmentKey);
		SameGroupVector<GqElement, GqGroup> commitmentsCb = CommitmentService
				.getCommitmentMatrix(updatedMatrixB, exponentsS, commitmentKey);

		zeroStatement = new ZeroStatement(commitmentsCa, commitmentsCb, y);
		zeroWitness = new ZeroWitness(matrixA, updatedMatrixB, exponentsR, exponentsS);
	}

	public GqGroupGenerator getGqGroupGenerator() {
		return gqGroupGenerator;
	}

	public int getM() {
		return m;
	}

	public int getN() {
		return n;
	}

	public ZeroArgumentService getZeroArgumentService() {
		return zeroArgumentService;
	}

	public ZeroStatement getZeroStatement() {
		return zeroStatement;
	}

	public ZeroWitness getZeroWitness() {
		return zeroWitness;
	}
}

