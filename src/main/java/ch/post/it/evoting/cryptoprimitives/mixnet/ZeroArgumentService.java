/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static ch.post.it.evoting.cryptoprimitives.SameGroupVector.toSameGroupVector;
import static ch.post.it.evoting.cryptoprimitives.mixnet.CommitmentService.getCommitment;
import static ch.post.it.evoting.cryptoprimitives.mixnet.CommitmentService.getCommitmentMatrix;
import static ch.post.it.evoting.cryptoprimitives.mixnet.CommitmentService.getCommitmentVector;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ch.post.it.evoting.cryptoprimitives.ConversionService;
import ch.post.it.evoting.cryptoprimitives.HashableBigInteger;
import ch.post.it.evoting.cryptoprimitives.SameGroupMatrix;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;

/**
 * Class in charge of providing a Zero Argument used in the Zero Argument proof.
 */
final class ZeroArgumentService {

	private final ElGamalMultiRecipientPublicKey publicKey;
	private final CommitmentKey commitmentKey;

	private final RandomService randomService;
	private final MixnetHashService hashService;

	private final Logger log = LoggerFactory.getLogger(ZeroArgumentService.class);

	ZeroArgumentService(final ElGamalMultiRecipientPublicKey publicKey, final CommitmentKey commitmentKey,
			final RandomService randomService, final MixnetHashService hashService) {

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
		checkArgument(y.getGroup().equals(exponentsR.getGroup()), "The statement y and witness exponents must be part of the same group.");

		// Ensure the statement and witness are corresponding.
		final SameGroupVector<GqElement, GqGroup> computedCommitmentsA = getCommitmentMatrix(matrixA, exponentsR, commitmentKey);
		checkArgument(commitmentsA.equals(computedCommitmentsA), "The statement's Ca commitments must be equal to the witness' commitment matrix A.");
		final SameGroupVector<GqElement, GqGroup> computedCommitmentsB = getCommitmentMatrix(matrixB, exponentsS, commitmentKey);
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
		final SameGroupVector<ZqElement, ZqGroup> a0 = SameGroupVector.from(randomService.genRandomVector(q, n));
		final SameGroupVector<ZqElement, ZqGroup> bm = SameGroupVector.from(randomService.genRandomVector(q, n));
		final ZqElement r0 = ZqElement.create(randomService.genRandomInteger(q), zqGroup);
		final ZqElement sm = ZqElement.create(randomService.genRandomInteger(q), zqGroup);
		final GqElement cA0 = getCommitment(a0, r0, commitmentKey);
		final GqElement cBm = getCommitment(bm, sm, commitmentKey);

		// Compute the D vector.
		final SameGroupMatrix<ZqElement, ZqGroup> augmentedMatrixA = matrixA.prependColumn(a0);
		final SameGroupMatrix<ZqElement, ZqGroup> augmentedMatrixB = matrixB.appendColumn(bm);

		final SameGroupVector<ZqElement, ZqGroup> d = computeDVector(augmentedMatrixA, augmentedMatrixB, y);

		// Compute t and c_d.
		final List<ZqElement> t = new ArrayList<>(randomService.genRandomVector(q, (2 * m) + 1));
		t.set(m + 1, ZqElement.create(BigInteger.ZERO, zqGroup));
		final SameGroupVector<GqElement, GqGroup> cd = getCommitmentVector(d, SameGroupVector.from(t), commitmentKey);

		// Compute x, later used to compute a', b', r', s' and t'.
		final byte[] hash = getHash(commitmentsA, commitmentsB, cA0, cBm, cd);
		final ZqElement x = ZqElement.create(ConversionService.byteArrayToInteger(hash), zqGroup);

		// To avoid computing multiple times the powers of x.
		final List<ZqElement> xExpI = IntStream.range(0, 2 * m + 1)
				.mapToObj(i -> x.exponentiate(BigInteger.valueOf(i)))
				.collect(Collectors.toCollection(ArrayList::new));

		// Compute vectors a' and b'.
		final SameGroupVector<ZqElement, ZqGroup> aPrime = IntStream.range(0, n)
				.mapToObj(j ->
						IntStream.range(0, m + 1)
								.mapToObj(i -> xExpI.get(i).multiply(augmentedMatrixA.get(j, i)))
								.reduce(zqGroup.getIdentity(), ZqElement::add))
				.collect(toSameGroupVector());

		final SameGroupVector<ZqElement, ZqGroup> bPrime = IntStream.range(0, n)
				.mapToObj(j ->
						IntStream.range(0, m + 1)
								.mapToObj(i -> xExpI.get(m - i).multiply(augmentedMatrixB.get(j, i)))
								.reduce(zqGroup.getIdentity(), ZqElement::add))
				.collect(toSameGroupVector());

		// Compute r', s' and t'.
		final SameGroupVector<ZqElement, ZqGroup> augmentedExponentsR = exponentsR.prepend(r0);
		final SameGroupVector<ZqElement, ZqGroup> augmentedExponentsS = exponentsS.append(sm);

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
	SameGroupVector<ZqElement, ZqGroup> computeDVector(final SameGroupMatrix<ZqElement, ZqGroup> firstMatrix,
			final SameGroupMatrix<ZqElement, ZqGroup> secondMatrix, final ZqElement y) {

		// Null checking.
		checkNotNull(firstMatrix);
		checkNotNull(secondMatrix);
		checkNotNull(y);

		// Cross matrix dimensions checking.
		checkArgument(firstMatrix.numRows() == secondMatrix.numRows(), "The two matrices must have the same number of rows.");
		checkArgument(firstMatrix.numColumns() == secondMatrix.numColumns(), "The two matrices must have the same number of columns.");

		if (firstMatrix.isEmpty()) {
			return SameGroupVector.of();
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

		return SameGroupVector.from(d);
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
	ZqElement starMap(final SameGroupVector<ZqElement, ZqGroup> firstVector, final SameGroupVector<ZqElement, ZqGroup> secondVector,
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
	 * @return <b>true</b> if the argument is valid for the given statement, <b>false</b> otherwise
	 */
	boolean verifyZeroArgument(final ZeroStatement statement, final ZeroArgument argument) {

		checkNotNull(statement);
		checkNotNull(argument);
		checkArgument(statement.getCommitmentsA().getGroup().equals(argument.getCd().getGroup()),
				"Statement and argument do not share the same group");

		SameGroupVector<GqElement, GqGroup> cA = statement.getCommitmentsA();
		SameGroupVector<GqElement, GqGroup> cd = argument.getCd();
		SameGroupVector<GqElement, GqGroup> cB = statement.getCommitmentsB();

		int m = cA.size();
		checkArgument((cd.size() - 2 * m) == 1, "The m of the statement should be equal to the m of the argument (2m+1)");

		ZqElement x = hashAndConvertX(statement, argument);

		boolean verifCd = BigInteger.ONE.equals(cd.get(m + 1).getValue());

		if (!verifCd) {
			log.error("cd.get(m + 1).getValue() {} should equal BigInteger.ONE", cd.get(m + 1).getValue());
			return false;
		}

		List<ZqElement> exponentiatedXs = IntStream.range(0, (2 * m) + 1)
				.mapToObj(i -> x.exponentiate(BigInteger.valueOf(i)))
				.collect(Collectors.toList());

		GqElement identity = cA.getGroup().getIdentity();

		SameGroupVector<GqElement, GqGroup> augmentedCA = cA.prepend(argument.getCA0());

		GqElement prodCa = IntStream.range(0, m + 1)
				.mapToObj(i -> augmentedCA.get(i).exponentiate(exponentiatedXs.get(i)))
				.reduce(identity, GqElement::multiply);

		SameGroupVector<ZqElement, ZqGroup> aPrime = argument.getAPrime();
		ZqElement rPrime = argument.getRPrime();

		GqElement commA = getCommitment(aPrime, rPrime, commitmentKey);
		boolean verifA = prodCa.equals(commA);

		if (!verifA) {
			log.error("commA {} and prodCa {} are not equal ", commA, prodCa);
			return false;
		}

		SameGroupVector<GqElement, GqGroup> augmentedCB = cB.append(argument.getCBm());

		GqElement prodCb = IntStream.range(0, m + 1)
				.mapToObj(i -> augmentedCB.get(m - i).exponentiate(exponentiatedXs.get(i)))
				.reduce(identity, GqElement::multiply);

		SameGroupVector<ZqElement, ZqGroup> bPrime = argument.getBPrime();
		ZqElement sPrime = argument.getSPrime();

		GqElement commB = getCommitment(bPrime, sPrime, commitmentKey);
		boolean verifB = prodCb.equals(commB);

		if (!verifB) {
			log.error("prodCb {} and commB {} are not equal ", prodCb, commB);
			return false;
		}

		GqElement prodCd = IntStream.range(0, (2 * m) + 1)
				.mapToObj(i -> cd.get(i).exponentiate(exponentiatedXs.get(i)))
				.reduce(identity, GqElement::multiply);

		SameGroupVector<ZqElement, ZqGroup> prod = SameGroupVector.of(starMap(aPrime, bPrime, statement.getY()));

		ZqElement tPrime = argument.getTPrime();
		GqElement commD = getCommitment(prod, tPrime, commitmentKey);

		boolean verifD = prodCd.equals(commD);

		if (!verifD) {
			log.error("prodCd {} and commD {} are not equal ", prodCd, commD);
			return false;
		}

		return true;

	}

	private ZqElement hashAndConvertX(ZeroStatement zeroStatement, ZeroArgument zeroArgument) {
		SameGroupVector<GqElement, GqGroup> cA = zeroStatement.getCommitmentsA();
		SameGroupVector<GqElement, GqGroup> cB = zeroStatement.getCommitmentsB();
		GqGroup group = cA.getGroup();

		GqElement cA0 = zeroArgument.getCA0();
		GqElement cBm = zeroArgument.getCBm();

		SameGroupVector<GqElement, GqGroup> cd = zeroArgument.getCd();

		final byte[] hash = getHash(cA, cB, cA0, cBm, cd);
		return ZqElement.create(ConversionService.byteArrayToInteger(hash), ZqGroup.sameOrderAs(group));
	}

	private byte[] getHash(SameGroupVector<GqElement, GqGroup> commitmentsA,
			SameGroupVector<GqElement, GqGroup> commitmentsB, GqElement cA0,
			GqElement cBm, SameGroupVector<GqElement, GqGroup> cd) {

		final GqGroup gqGroup = commitmentsA.get(0).getGroup();
		BigInteger p = gqGroup.getP();
		BigInteger q = gqGroup.getQ();

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
