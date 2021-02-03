package ch.post.it.evoting.cryptoprimitives.mixnet;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
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
import ch.post.it.evoting.cryptoprimitives.random.RandomService;

public class HadamardArgumentService {

	private final RandomService randomService;
	private final HashService hashService;
	private final ElGamalMultiRecipientPublicKey publicKey;
	private final CommitmentKey commitmentKey;
	private final ZeroArgumentService zeroArgumentService;

	HadamardArgumentService(final RandomService randomService, final HashService hashService, final ElGamalMultiRecipientPublicKey publicKey,
			final CommitmentKey commitmentKey) {
		checkNotNull(randomService);
		checkNotNull(hashService);
		checkNotNull(publicKey);
		checkNotNull(commitmentKey);

		// Check group and dimension of the public and commitment key
		checkArgument(publicKey.getGroup().equals(commitmentKey.getGroup()),
				"The public key and the commitment key must belong to the same group.");
		checkArgument(publicKey.size() == commitmentKey.size(),
				"The public key and the commitment key must have the same size.");

		this.randomService = randomService;
		this.hashService = hashService;
		this.publicKey = publicKey;
		this.commitmentKey = commitmentKey;
		this.zeroArgumentService = new ZeroArgumentService(publicKey, commitmentKey, randomService, hashService);
	}

	HadamardArgument getHadamardArgument(final HadamardStatement statement, final HadamardWitness witness) {
		checkNotNull(statement);
		checkNotNull(witness);

		// Extract commitments, matrix, vector and exponents
		final SameGroupVector<GqElement, GqGroup> cA = statement.getCommitmentsA();
		final GqElement cb = statement.getCommitmentB();
		@SuppressWarnings("squid:S00117")
		final SameGroupMatrix<ZqElement, ZqGroup> A = witness.getMatrixA();
		final SameGroupVector<ZqElement, ZqGroup> b = witness.getVectorB();
		final SameGroupVector<ZqElement, ZqGroup> r = witness.getExponentsR();
		final ZqElement s = witness.getExponentS();

		// Check dimensions and groups
		final int m = A.columnSize();
		final int n = A.rowSize();
		final int k = commitmentKey.size();
		checkArgument(cA.size() == m, "The commitments for A must have as many elements as matrix A has rows.");
		checkArgument(cA.getGroup().getQ().equals(A.getGroup().getQ()), "The matrix A and its commitments must have the same group order q.");
		checkArgument(n <= k, "The number of columns in the matrix must be smaller than the commitment key size.");

		// Ensure statement corresponds to witness
		checkArgument(m >= 2, "The matrix must have at least 2 columns.");
		final SameGroupVector<GqElement, GqGroup> commitments = CommitmentService.getCommitmentMatrix(A, r, commitmentKey);
		checkArgument(cA.equals(commitments),
				"The commitments A must correspond to the commitment to matrix A with exponents r and the given commitment key.");
		final GqElement commitment = CommitmentService.getCommitment(b, s, commitmentKey);
		checkArgument(cb.equals(commitment),
				"The commitment b must correspond to the commitment to vector b with exponent s and the given commitment key.");
		checkArgument(b.equals(getHadamardProduct(A, A.columnSize() - 1)),
				"The vector b must correspond to the product of the column vectors of the matrix A.");

		// Start operation
		final ZqGroup zqGroup = A.getGroup();
		final GqGroup gqGroup = cb.getGroup();
		final BigInteger q = gqGroup.getQ();
		final BigInteger p = gqGroup.getP();

		// Calculate b_0, ..., b_(m-1)
		final List<SameGroupVector<ZqElement, ZqGroup>> bList = IntStream.range(0, m)
				.mapToObj(j -> getHadamardProduct(A, j))
				.collect(Collectors.toList());

		// Calculate s_0, ..., s_(m-1)
		final List<ZqElement> sList = new ArrayList<>(m);
		sList.add(0, r.get(0));
		sList.addAll(1,
				Stream.generate(() -> ZqElement.create(randomService.genRandomInteger(q), zqGroup))
						.limit(m - 2L)
						.collect(Collectors.toList()));
		sList.add(m - 1, s);

		// Calculate c_(B_0), ..., c_(B_(m-1))
		final List<GqElement> cBList = new ArrayList<>(m);
		cBList.add(0, cA.get(0));
		cBList.addAll(1, IntStream.range(1, m - 1)
				.mapToObj(j -> CommitmentService.getCommitment(bList.get(j), sList.get(j), commitmentKey))
				.collect(Collectors.toList()));
		cBList.add(m - 1, cb);

		// Calculate x
		final byte[] hashX = hashService.recursiveHash(
				p,
				q,
				publicKey.stream().map(GqElement::getValue).collect(Collectors.toList()),
				commitmentKey.stream().map(GqElement::getValue).collect(Collectors.toList()),
				cA.stream().map(GroupElement::getValue).collect(Collectors.toList()),
				cb.getValue(),
				cBList.stream().map(GroupElement::getValue)
		);
		final ZqElement x = ZqElement.create(ConversionService.byteArrayToInteger(hashX), zqGroup);

		// Calculate y
		final byte[] hashY = hashService.recursiveHash(
				"1",
				p,
				q,
				publicKey.stream().map(GqElement::getValue).collect(Collectors.toList()),
				commitmentKey.stream().map(GqElement::getValue).collect(Collectors.toList()),
				cA.stream().map(GroupElement::getValue).collect(Collectors.toList()),
				cb.getValue(),
				cBList.stream().map(GroupElement::getValue)
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
		final SameGroupVector<GqElement, GqGroup> cDiList = IntStream.range(0, m - 1)
				.mapToObj(i -> cBList.get(i).exponentiate(xExpI.get(i + 1)))
				.collect(Collectors.collectingAndThen(Collectors.toList(), SameGroupVector::new));

		// Calculate t_0, ..., t_(m-2)
		final SameGroupVector<ZqElement, ZqGroup> tiList = IntStream.range(0, m - 1)
				.mapToObj(i -> xExpI.get(i + 1).multiply(sList.get(i)))
				.collect(Collectors.collectingAndThen(Collectors.toList(), SameGroupVector::new));

		// Calculate d
		final SameGroupVector<ZqElement, ZqGroup> dElements = IntStream.range(0, n)
				.mapToObj(i -> IntStream.range(1, m)
						.mapToObj(j -> xExpI.get(j).multiply(bList.get(j).get(i)))
						.reduce(zqGroup.getIdentity(), ZqElement::add))
				.collect(Collectors.collectingAndThen(Collectors.toList(), SameGroupVector::new));

		// Calculate c_D
		final GqElement cD = IntStream.range(1, m)
				.mapToObj(i -> cBList.get(i).exponentiate(xExpI.get(i)))
				.reduce(gqGroup.getIdentity(), GqElement::multiply);

		// Calculate t
		final ZqElement t = IntStream.range(1, m)
				.mapToObj(i -> xExpI.get(i).multiply(sList.get(i)))
				.reduce(zqGroup.getIdentity(), ZqElement::add);

		// (-1, ..., -1) and c_(-1)
		final SameGroupVector<ZqElement, ZqGroup> minusOnes = Stream.generate(() -> ZqElement.create(q.subtract(BigInteger.ONE), zqGroup)).limit(n)
				.collect(Collectors.collectingAndThen(Collectors.toList(), SameGroupVector::new));
		final ZqElement zero = zqGroup.getIdentity();
		final GqElement cMinusOne = CommitmentService.getCommitment(minusOnes, zero, commitmentKey);

		// Calculate and return the zero argument.
		// Beware that we name the variables as they are called within the zero argument (and not how they are called in the Hadamard argument).
		// Therefore, D becomes B and T becomes S.
		// Create statement
		final SameGroupVector<GqElement, GqGroup> zCommitmentsA = cA.append(cMinusOne).stream().skip(1)
				.collect(Collectors.collectingAndThen(Collectors.toList(), SameGroupVector::new));
		final SameGroupVector<GqElement, GqGroup> zCommitmentsB = cDiList.append(cD);
		ZeroStatement zStatement = new ZeroStatement(zCommitmentsA, zCommitmentsB, y);
		// Create witness
		final SameGroupMatrix<ZqElement, ZqGroup> zMatrixA = SameGroupMatrix
				.fromColumns(A.appendColumn(minusOnes).columnStream().skip(1).map(a -> a.stream().collect(Collectors.toList()))
						.collect(Collectors.toList()));
		final SameGroupMatrix<ZqElement, ZqGroup> zMatrixB = SameGroupMatrix.fromColumns(diList).appendColumn(dElements);
		final SameGroupVector<ZqElement, ZqGroup> zExponentsR = r.append(zero).stream().skip(1)
				.collect(Collectors.collectingAndThen(Collectors.toList(), SameGroupVector::new));
		final SameGroupVector<ZqElement, ZqGroup> zExponentsS = tiList.append(t);
		ZeroWitness zWitness = new ZeroWitness(zMatrixA, zMatrixB, zExponentsR, zExponentsS);

		// Prepare Hadamard argument
		SameGroupVector<GqElement, GqGroup> cB = new SameGroupVector<>(cBList);
		ZeroArgument zeroArgument = zeroArgumentService.getZeroArgument(zStatement, zWitness);

		return new HadamardArgument(cB, zeroArgument);
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
	SameGroupVector<ZqElement, ZqGroup> getHadamardProduct(final SameGroupMatrix<ZqElement, ZqGroup> matrix, final int j) {
		checkNotNull(matrix);
		checkArgument(j >= 0, "The column index must be greater than or equal to 0.");
		checkArgument(j < matrix.columnSize(), "The column index must be smaller than the number of rows in the matrix.");
		ZqElement one = ZqElement.create(BigInteger.ONE, matrix.getGroup());
		int n = matrix.rowSize();
		return IntStream.range(0, n)
				.mapToObj(i -> matrix.getRow(i).stream()
						.limit(j + 1L)
						.reduce(one, ZqElement::multiply))
				.collect(Collectors.collectingAndThen(Collectors.toList(), SameGroupVector::new));
	}
}
