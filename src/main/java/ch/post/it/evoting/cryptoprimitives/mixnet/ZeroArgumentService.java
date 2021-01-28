/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import ch.post.it.evoting.cryptoprimitives.ConversionService;
import ch.post.it.evoting.cryptoprimitives.HashService;
import ch.post.it.evoting.cryptoprimitives.SameGroupMatrix;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.mixnet.ZeroArgument.ZeroArgumentBuilder;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;

/**
 * Class in charge of providing a Zero Argument used in the Zero Argument proof.
 */
final class ZeroArgumentService {

	private final ElGamalMultiRecipientPublicKey publicKey;
	private final CommitmentKey commitmentKey;

	private final RandomService randomService;
	private final HashService hashService;

	ZeroArgumentService(final ElGamalMultiRecipientPublicKey publicKey, final CommitmentKey commitmentKey,
			final RandomService randomService, final HashService hashService) {

		// Null checking.
		checkNotNull(publicKey);
		checkNotNull(commitmentKey);
		checkNotNull(randomService);
		checkNotNull(hashService);

		// Dimensions checking.
		checkArgument(publicKey.size() == commitmentKey.size(), "The public and commitment keys do not have compatible sizes.");

		// Group checking.
		checkArgument(publicKey.getGroup().equals(commitmentKey.getGroup()), "The public and commitment keys are not from the same group.");

		this.publicKey = publicKey;
		this.commitmentKey = commitmentKey;
		this.randomService = randomService;
		this.hashService = hashService;
	}

	/**
	 * Generate an argument of knowledge of the values <code>a<sub>1</sub>, b<sub>0</sub>, ..., a<sub>m</sub>, b<sub>m-1</sub></code> such that
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

		final SameGroupMatrix<ZqElement, ZqGroup> matrixA = witness.getMatrixA();
		final SameGroupMatrix<ZqElement, ZqGroup> matrixB = witness.getMatrixB();
		final SameGroupVector<ZqElement, ZqGroup> exponentsR = witness.getExponentsR();
		final SameGroupVector<ZqElement, ZqGroup> exponentsS = witness.getExponentsS();
		final SameGroupVector<GqElement, GqGroup> commitmentsA = statement.getCommitmentsA();
		final SameGroupVector<GqElement, GqGroup> commitmentsB = statement.getCommitmentsB();
		final ZqElement y = statement.getY();

		// Cross dimensions checking between statement and witness.
		checkArgument(commitmentsA.size() == exponentsR.size(), "The statement commitments must have the same size as the witness exponents.");

		// Cross group checking.
		checkArgument(y.getGroup().equals(exponentsR.getGroup()), "The statement y and exponents must be part of the same group.");

		// Ensure the statement and witness are corresponding.
		final List<GqElement> computedCommitmentsA = CommitmentService.getCommitmentMatrix(matrixA, exponentsR, commitmentKey);
		checkArgument(commitmentsA.equals(new SameGroupVector<>(computedCommitmentsA)),
				"The statement's Ca commitments must be equal to the witness' commitment matrix A.");
		final List<GqElement> computedCommitmentsB = CommitmentService.getCommitmentMatrix(matrixB, exponentsS, commitmentKey);
		checkArgument(commitmentsB.equals(new SameGroupVector<>(computedCommitmentsB)),
				"The statement's Cb commitments must be equal to the witness' commitment matrix B.");

		final ZqGroup zqGroup = y.getGroup();

		// The specifications uses the indices [1,m] for matrixA and [0,m-1] for matrixB. In the code, we use [0,m-1] for both indices.
		final int m = matrixA.columnSize();
		final ZqElement starMapSum = IntStream.range(0, m)
				.mapToObj(i -> starMap(matrixA.getColumn(i), matrixB.getColumn(i), y))
				.reduce(zqGroup.getIdentity(), ZqElement::add);
		checkArgument(zqGroup.getIdentity().equals(starMapSum),
				"The starMap sum between the witness' matrices rows are not equal to ZqGroup identity.");

		// Algorithm operations.

		final int n = matrixA.rowSize();
		final List<ZqElement> a0 = generateRandomZqElementList(n, zqGroup);
		final List<ZqElement> bm = generateRandomZqElementList(n, zqGroup);
		final ZqElement r0 = ZqElement.create(randomService.genRandomInteger(zqGroup.getQ()), zqGroup);
		final ZqElement sm = ZqElement.create(randomService.genRandomInteger(zqGroup.getQ()), zqGroup);
		final GqElement cA0 = CommitmentService.getCommitment(a0, r0, commitmentKey);
		final GqElement cBm = CommitmentService.getCommitment(bm, sm, commitmentKey);

		// Compute the D vector.
		final SameGroupMatrix<ZqElement, ZqGroup> augmentedMatrixA = matrixA.prependColumn(a0);
		final SameGroupMatrix<ZqElement, ZqGroup> augmentedMatrixB = matrixB.appendColumn(bm);

		final List<ZqElement> d = computeDVector(augmentedMatrixA.toLists(), augmentedMatrixB.toLists(), y);

		// Compute t and c_d.
		final List<ZqElement> t = new ArrayList<>(generateRandomZqElementList(2 * m + 1, zqGroup));
		t.set(m + 1, ZqElement.create(BigInteger.ZERO, zqGroup));
		final List<GqElement> cd = CommitmentService.getCommitmentVector(d, t, commitmentKey);

		// Compute x, later used to compute a', b', r', s' and t'.
		final GqGroup gqGroup = commitmentsA.get(0).getGroup();
		final byte[] hash = hashService.recursiveHash(
				gqGroup.getP(),
				gqGroup.getQ(),
				publicKey.stream()
						.map(GqElement::getValue)
						.collect(Collectors.toList()),
				commitmentKey.stream()
						.map(GroupElement::getValue)
						.collect(Collectors.toList()),
				cA0.getValue(),
				cBm.getValue(),
				cd.stream()
						.map(GqElement::getValue)
						.collect(Collectors.toList()),
				commitmentsB.stream()
						.map(GroupElement::getValue)
						.collect(Collectors.toList()),
				commitmentsA.stream()
						.map(GroupElement::getValue)
						.collect(Collectors.toList())
		);
		final ZqElement x = ZqElement.create(ConversionService.byteArrayToInteger(hash), zqGroup);

		// To avoid computing multiple times the powers of x.
		final List<ZqElement> xExpI = IntStream.range(0, 2 * m + 1)
				.mapToObj(i -> x.exponentiate(BigInteger.valueOf(i)))
				.collect(Collectors.toCollection(ArrayList::new));
		final List<ZqElement> xExpMMinusI = IntStream.range(0, m + 1)
				.mapToObj(i -> x.exponentiate(BigInteger.valueOf((long) m - i)))
				.collect(Collectors.toCollection(ArrayList::new));

		// Compute vectors a' and b'.
		final List<ZqElement> aPrime = IntStream.range(0, n)
				.mapToObj(j ->
						IntStream.range(0, m + 1)
								.mapToObj(i -> xExpI.get(i).multiply(augmentedMatrixA.get(j, i)))
								.reduce(zqGroup.getIdentity(), ZqElement::add))
				.collect(Collectors.toList());

		final List<ZqElement> bPrime = IntStream.range(0, n)
				.mapToObj(j ->
						IntStream.range(0, m + 1)
								.mapToObj(i -> xExpMMinusI.get(i).multiply(augmentedMatrixB.get(j, i)))
								.reduce(zqGroup.getIdentity(), ZqElement::add))
				.collect(Collectors.toList());

		// Add newly created elements to the exponents vectors.
		final SameGroupVector<ZqElement, ZqGroup> augmentedExponentsR = exponentsR.prepend(r0);
		final SameGroupVector<ZqElement, ZqGroup> augmentedExponentsS = exponentsS.append(sm);

		// Compute r', s' and t'.
		final ZqElement rPrime = IntStream.range(0, m + 1)
				.mapToObj(i -> xExpI.get(i).multiply(augmentedExponentsR.get(i)))
				.reduce(zqGroup.getIdentity(), ZqElement::add);

		final ZqElement sPrime = IntStream.range(0, m + 1)
				.mapToObj(i -> xExpMMinusI.get(i).multiply(augmentedExponentsS.get(i)))
				.reduce(zqGroup.getIdentity(), ZqElement::add);

		final ZqElement tPrime = IntStream.range(0, 2 * m + 1)
				.mapToObj(i -> xExpI.get(i).multiply(t.get(i)))
				.reduce(zqGroup.getIdentity(), ZqElement::add);

		// Construct the ZeroArgument with all computed parameters.
		final ZeroArgumentBuilder zeroArgumentBuilder = new ZeroArgumentBuilder();
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
	 * Compute the vector <b>d</b> for the GetZeroArgument algorithm. The input matrices must comply with the following:
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
	List<ZqElement> computeDVector(final List<List<ZqElement>> firstMatrix, final List<List<ZqElement>> secondMatrix, final ZqElement y) {
		// Null checking.
		checkNotNull(firstMatrix);
		checkNotNull(secondMatrix);
		checkNotNull(y);
		checkArgument(firstMatrix.stream().allMatch(Objects::nonNull), "First matrix rows must not be null.");
		checkArgument(secondMatrix.stream().allMatch(Objects::nonNull), "Second matrix rows must not be null.");
		checkArgument(firstMatrix.stream().flatMap(Collection::stream).allMatch(Objects::nonNull), "First matrix elements must not be null.");
		checkArgument(secondMatrix.stream().flatMap(Collection::stream).allMatch(Objects::nonNull), "Second matrix elements must not be null.");

		// Immutable copies and individual matrix validation (group and size).
		final SameGroupMatrix<ZqElement, ZqGroup> firstMatrixCopy = SameGroupMatrix.fromRows(firstMatrix);
		final SameGroupMatrix<ZqElement, ZqGroup> secondMatrixCopy = SameGroupMatrix.fromRows(secondMatrix);

		// Cross matrix dimensions checking.
		checkArgument(firstMatrixCopy.rowSize() == secondMatrixCopy.rowSize(), "The two matrices must have the same number of rows.");
		checkArgument(firstMatrixCopy.columnSize() == secondMatrixCopy.columnSize(), "The two matrices must have the same number of columns.");

		if (firstMatrixCopy.isEmpty()) {
			return Collections.emptyList();
		}

		//Cross matrix group checking.
		checkArgument(firstMatrixCopy.getGroup().equals(secondMatrixCopy.getGroup()), "The elements of both matrices must be in the same group.");
		checkArgument(y.getGroup().equals(firstMatrixCopy.getGroup()), "The value y must be in the same group as the elements of the matrices.");

		// Computing the d vector.
		final int m = firstMatrixCopy.columnSize() - 1;
		final LinkedList<ZqElement> d = new LinkedList<>();
		final ZqGroup group = y.getGroup();
		for (int k = 0; k <= 2 * m; k++) {
			ZqElement dk = group.getIdentity();
			for (int i = Math.max(0, k - m); i <= m; i++) {
				final int j = (m - k) + i;
				if (j > m) {
					break;
				}
				dk = dk.add(starMap(firstMatrixCopy.getColumn(i), secondMatrixCopy.getColumn(j), y));
			}
			d.add(dk);
		}

		return d;
	}

	/**
	 * Define the bilinear map represented by the star operator &#8902; in the specification. All elements must be in the same group. The algorithm
	 * defined by the value {@code y} is the following:
	 * <p>
	 * (a<sub>0</sub>,..., a<sub>n-1</sub>) &#8902; (b<sub>0</sub>,...,b<sub>n-1</sub>) = &sum;<sub>j=0</sub><sup>n-1</sup> a<sub>j</sub> &middot;
	 * b<sub>j</sub> &middot; y<sup>j</sup>
	 *
	 * @param firstVector  a, the first vector.
	 * @param secondVector b, the second vector.
	 * @return The sum &sum;<sub>j=0</sub><sup>n-1</sup> a<sub>j</sub> &middot; b<sub>j</sub> &middot; y<sup>j</sup>
	 */
	ZqElement starMap(final List<ZqElement> firstVector, final List<ZqElement> secondVector, final ZqElement y) {
		// Null checking.
		checkNotNull(firstVector);
		checkNotNull(secondVector);
		checkNotNull(y);
		checkArgument(firstVector.stream().allMatch(Objects::nonNull), "The elements of the first vector must not be null.");
		checkArgument(secondVector.stream().allMatch(Objects::nonNull), "The elements of the second vector must not be null.");

		// Immutable copies and individual group check.
		final SameGroupVector<ZqElement, ZqGroup> firstVectorCopy = new SameGroupVector<>(firstVector);
		final SameGroupVector<ZqElement, ZqGroup> secondVectorCopy = new SameGroupVector<>(secondVector);

		// Dimensions checking.
		checkArgument(firstVectorCopy.size() == secondVectorCopy.size(), "The provided vectors must have the same size.");

		// Handle empty vectors.
		if (firstVectorCopy.isEmpty()) {
			return y.getGroup().getIdentity();
		}

		// Group checking.
		checkArgument(firstVectorCopy.getGroup().equals(secondVectorCopy.getGroup()), "The elements of both vectors must be in the same group.");
		checkArgument(firstVectorCopy.getGroup().equals(y.getGroup()), "The value y must be in the same group as the vectors elements");
		final ZqGroup group = y.getGroup();

		// StarMap computing.
		final int n = firstVectorCopy.size();
		return IntStream.range(0, n)
				.mapToObj(j -> firstVectorCopy.get(j)
						.multiply(secondVectorCopy.get(j))
						.multiply(y.exponentiate(BigInteger.valueOf(j))))
				.reduce(group.getIdentity(), ZqElement::add);
	}

	/**
	 * Generate a random immutable vector of {@link ZqElement} in the specified {@code group}.
	 *
	 * @param numElements the number of elements to generate.
	 * @return a vector of {@code numElements} random {@link ZqElement}.
	 */
	private List<ZqElement> generateRandomZqElementList(final int numElements, final ZqGroup group) {
		return Stream.generate(() -> ZqElement.create(randomService.genRandomInteger(group.getQ()), group)).limit(numElements)
				.collect(Collectors.toList());
	}
}
