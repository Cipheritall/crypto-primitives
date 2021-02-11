/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static java.util.Arrays.asList;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import ch.post.it.evoting.cryptoprimitives.HashService;
import ch.post.it.evoting.cryptoprimitives.SameGroupMatrix;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GqGroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;

@DisplayName("A ZeroArgumentService")
@ExtendWith(MockitoExtension.class)
class ZeroArgumentServiceTest {

	private static final BigInteger ZERO = BigInteger.valueOf(0);
	private static final BigInteger ONE = BigInteger.valueOf(1);
	private static final BigInteger TWO = BigInteger.valueOf(2);
	private static final BigInteger THREE = BigInteger.valueOf(3);
	private static final BigInteger FOUR = BigInteger.valueOf(4);
	private static final BigInteger FIVE = BigInteger.valueOf(5);
	private static final BigInteger SIX = BigInteger.valueOf(6);
	private static final BigInteger SEVEN = BigInteger.valueOf(7);
	private static final BigInteger EIGHT = BigInteger.valueOf(8);
	private static final BigInteger NINE = BigInteger.valueOf(9);
	private static final BigInteger TEN = BigInteger.valueOf(10);
	private static final BigInteger ELEVEN = BigInteger.valueOf(11);
	private static final int KEY_ELEMENTS_NUMBER = 10;
	private static final SecureRandom secureRandom = new SecureRandom();

	private static ZqGroup zqGroup;
	private static GqGroup gqGroup;
	private static ZqGroupGenerator zqGroupGenerator;
	private static GqGroupGenerator gqGroupGenerator;
	private static ZeroArgumentService zeroArgumentService;
	private static CommitmentKey commitmentKey;
	private static ElGamalMultiRecipientPublicKey publicKey;
	private static RandomService randomService;
	private static HashService hashService;

	@BeforeAll
	static void setUpAll() throws Exception {
		// GqGroup and corresponding ZqGroup set up.
		gqGroup = GqGroupTestData.getGroup();
		zqGroup = ZqGroup.sameOrderAs(gqGroup);
		zqGroupGenerator = new ZqGroupGenerator(zqGroup);
		gqGroupGenerator = new GqGroupGenerator(gqGroup);

		// Generate publicKey and commitmentKey.
		final GqElement h = gqGroupGenerator.genNonIdentityNonGeneratorMember();
		final List<GqElement> g = Stream.generate(gqGroupGenerator::genNonIdentityNonGeneratorMember).limit(KEY_ELEMENTS_NUMBER)
				.collect(Collectors.toList());
		commitmentKey = new CommitmentKey(h, g);

		final List<GqElement> pkElements = Stream.generate(gqGroupGenerator::genNonIdentityNonGeneratorMember).limit(KEY_ELEMENTS_NUMBER)
				.collect(Collectors.toList());
		publicKey = new ElGamalMultiRecipientPublicKey(pkElements);

		// Init services.
		randomService = new RandomService();
		hashService = new HashService(MessageDigest.getInstance("SHA-256"));

		zeroArgumentService = new ZeroArgumentService(publicKey, commitmentKey, randomService, hashService);
	}

	@Test
	@DisplayName("constructed with any null parameter throws NullPointerException")
	void constructNullParams() {
		assertAll(
				() -> assertThrows(NullPointerException.class,
						() -> new ZeroArgumentService(null, commitmentKey, randomService, hashService)),
				() -> assertThrows(NullPointerException.class,
						() -> new ZeroArgumentService(publicKey, null, randomService, hashService)),
				() -> assertThrows(NullPointerException.class,
						() -> new ZeroArgumentService(publicKey, commitmentKey, null, hashService)),
				() -> assertThrows(NullPointerException.class,
						() -> new ZeroArgumentService(publicKey, commitmentKey, randomService, null))
		);
	}

	@Test
	@DisplayName("constructed with keys having incompatible sizes throws IllegalArgumentException")
	void constructIncompatibleSizeKeys() {
		// Create public key of different size.
		final List<GqElement> pkElements = Stream.generate(gqGroupGenerator::genNonIdentityNonGeneratorMember).limit(1).collect(Collectors.toList());
		final ElGamalMultiRecipientPublicKey otherPublicKey = new ElGamalMultiRecipientPublicKey(pkElements);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ZeroArgumentService(otherPublicKey, commitmentKey, randomService, hashService));
		assertEquals("The public and commitment keys do not have compatible sizes.", exception.getMessage());
	}

	@Test
	@DisplayName("constructed with keys from different groups throws IllegalArgumentException")
	void constructDiffGroupKeys() {
		// Create public key from other group.
		final GqGroupGenerator otherGqGroupGenerator = new GqGroupGenerator(GqGroupTestData.getDifferentGroup(gqGroup));
		final List<GqElement> pkElements = Stream.generate(otherGqGroupGenerator::genNonIdentityNonGeneratorMember).limit(KEY_ELEMENTS_NUMBER)
				.collect(Collectors.toList());
		final ElGamalMultiRecipientPublicKey otherPublicKey = new ElGamalMultiRecipientPublicKey(pkElements);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ZeroArgumentService(otherPublicKey, commitmentKey, randomService, hashService));
		assertEquals("The public and commitment keys are not from the same group.", exception.getMessage());
	}

	@Nested
	@DisplayName("computeDVector")
	class ComputeDVectorTest {

		private static final int RANDOM_UPPER_BOUND = 10;

		private int n;
		private int m;
		private SameGroupMatrix<ZqElement, ZqGroup> firstMatrix;
		private SameGroupMatrix<ZqElement, ZqGroup> secondMatrix;
		private ZqElement y;

		@BeforeEach
		void setUp() {
			n = secureRandom.nextInt(RANDOM_UPPER_BOUND) + 1;
			m = secureRandom.nextInt(RANDOM_UPPER_BOUND) + 1;
			firstMatrix = zqGroupGenerator.generateRandomZqElementMatrix(n, m + 1);
			secondMatrix = zqGroupGenerator.generateRandomZqElementMatrix(n, m + 1);
			y = ZqElement.create(randomService.genRandomInteger(zqGroup.getQ()), zqGroup);
		}

		@Test
		@DisplayName("with any null parameter throws NullPointerException")
		void computeDVectorNullParams() {
			final SameGroupMatrix<ZqElement, ZqGroup> emptyMatrix = SameGroupMatrix.fromRows(Collections.emptyList());

			assertAll(
					() -> assertThrows(NullPointerException.class, () -> zeroArgumentService.computeDVector(null, secondMatrix, y)),
					() -> assertThrows(NullPointerException.class, () -> zeroArgumentService.computeDVector(firstMatrix, null, y)),
					() -> assertThrows(NullPointerException.class, () -> zeroArgumentService.computeDVector(firstMatrix, secondMatrix, null)),
					() -> assertThrows(NullPointerException.class, () -> zeroArgumentService.computeDVector(null, emptyMatrix, y)),
					() -> assertThrows(NullPointerException.class, () -> zeroArgumentService.computeDVector(emptyMatrix, null, y)),
					() -> assertThrows(NullPointerException.class, () -> zeroArgumentService.computeDVector(emptyMatrix, emptyMatrix, null))
			);
		}

		@Test
		@DisplayName("with matrices having unequal number of rows throws IllegalArgumentException")
		void computeDVectorDifferentSizeLines() {
			// Generate a first matrix with an additional row.
			final SameGroupMatrix<ZqElement, ZqGroup> otherMatrix = zqGroupGenerator.generateRandomZqElementMatrix(n + 1, m + 1);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.computeDVector(otherMatrix, secondMatrix, y));
			assertEquals("The two matrices must have the same number of rows.", exception.getMessage());

			// With empty matrices.
			final SameGroupMatrix<ZqElement, ZqGroup> emptyMatrix = SameGroupMatrix.fromRows(Collections.emptyList());
			final IllegalArgumentException exceptionSecondEmpty = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.computeDVector(otherMatrix, emptyMatrix, y));
			assertEquals("The two matrices must have the same number of rows.", exceptionSecondEmpty.getMessage());

			final IllegalArgumentException exceptionFirstEmpty = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.computeDVector(emptyMatrix, secondMatrix, y));
			assertEquals("The two matrices must have the same number of rows.", exceptionFirstEmpty.getMessage());
		}

		@Test
		@DisplayName("with matrices with different number of columns throws IllegalArgumentException")
		void computeDVectorDifferentSizeColumns() {
			final SameGroupMatrix<ZqElement, ZqGroup> otherFirstMatrix = zqGroupGenerator.generateRandomZqElementMatrix(n, m);
			final SameGroupMatrix<ZqElement, ZqGroup> otherSecondMatrix = zqGroupGenerator.generateRandomZqElementMatrix(n, m + 1);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.computeDVector(otherFirstMatrix, otherSecondMatrix, y));
			assertEquals("The two matrices must have the same number of columns.", exception.getMessage());
		}

		@Test
		@DisplayName("with second matrix having elements of different group than the first matrix throws IllegalArgumentException")
		void computeDVectorMatricesDifferentGroup() {
			// Get a second matrix in a different ZqGroup.
			final ZqGroup otherZqGroup = getDifferentZqGroup();
			final ZqGroupGenerator otherZqGroupGenerator = new ZqGroupGenerator(otherZqGroup);
			final SameGroupMatrix<ZqElement, ZqGroup> differentGroupSecondMatrix = otherZqGroupGenerator.generateRandomZqElementMatrix(n, m + 1);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.computeDVector(firstMatrix, differentGroupSecondMatrix, y));
			assertEquals("The elements of both matrices must be in the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("with y from a different group throws IllegalArgumentException")
		void computeDVectorYDifferentGroup() {
			// Get a different ZqGroup.
			final ZqGroup differentZqGroup = getDifferentZqGroup();

			// Create a y value from a different group.
			final ZqElement differentGroupY = ZqElement.create(randomService.genRandomInteger(differentZqGroup.getQ()), differentZqGroup);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.computeDVector(firstMatrix, secondMatrix, differentGroupY));
			assertEquals("The value y must be in the same group as the elements of the matrices.", exception.getMessage());
		}

		@RepeatedTest(100)
		@DisplayName("with random values gives expected d vector length")
		void computeDVectorTest() {
			assertEquals(2 * m + 1, zeroArgumentService.computeDVector(firstMatrix, secondMatrix, y).size());
		}

		@Test
		@DisplayName("with empty matrices gives empty result vector")
		void computeDVectorEmptyMatrices() {
			final SameGroupVector<ZqElement, ZqGroup> emptyD = SameGroupVector.of();
			final SameGroupMatrix<ZqElement, ZqGroup> firstEmptyMatrix = SameGroupMatrix.fromRows(Collections.emptyList());
			final SameGroupMatrix<ZqElement, ZqGroup> secondEmptyMatrix = SameGroupMatrix.fromRows(Collections.emptyList());

			assertEquals(emptyD, zeroArgumentService.computeDVector(firstEmptyMatrix, secondEmptyMatrix, y));
		}

		@Test
		@DisplayName("with matrices with empty columns gives empty result vector")
		void computeDVectorEmptyColumns() {
			final SameGroupVector<ZqElement, ZqGroup> emptyD = SameGroupVector.of();
			final SameGroupMatrix<ZqElement, ZqGroup> firstEmptyMatrix = SameGroupMatrix.fromColumns(Collections.emptyList());
			final SameGroupMatrix<ZqElement, ZqGroup> secondEmptyMatrix = SameGroupMatrix.fromColumns(Collections.emptyList());

			assertEquals(emptyD, zeroArgumentService.computeDVector(firstEmptyMatrix, secondEmptyMatrix, y));
		}

		@Test
		@DisplayName("with simple values gives expected result")
		void computeDVectorSimpleValuesTest() {
			// Small Zq group.
			final ZqGroup group = new ZqGroup(ELEVEN);

			// Construct the two matrices and value y.
			final List<ZqElement> a0 = asList(ZqElement.create(ZERO, group), ZqElement.create(TWO, group));
			final List<ZqElement> a1 = asList(ZqElement.create(FOUR, group), ZqElement.create(SIX, group));
			final List<ZqElement> b0 = asList(ZqElement.create(ONE, group), ZqElement.create(THREE, group));
			final List<ZqElement> b1 = asList(ZqElement.create(FIVE, group), ZqElement.create(SEVEN, group));
			final SameGroupMatrix<ZqElement, ZqGroup> firstMatrix = SameGroupMatrix.fromRows(asList(a0, a1));
			final SameGroupMatrix<ZqElement, ZqGroup> secondMatrix = SameGroupMatrix.fromRows(asList(b0, b1));
			final ZqElement y = ZqElement.create(EIGHT, group);

			// Expected d vector.
			final SameGroupVector<ZqElement, ZqGroup> expected = SameGroupVector.of(
					ZqElement.create(TEN, group), ZqElement.create(ONE, group), ZqElement.create(ZERO, group));

			assertEquals(expected, zeroArgumentService.computeDVector(firstMatrix, secondMatrix, y));
		}
	}

	@Nested
	@DisplayName("starMap")
	class StarMapTest {

		private static final int RANDOM_UPPER_BOUND = 10;

		private int n;
		private SameGroupVector<ZqElement, ZqGroup> firstVector;
		private SameGroupVector<ZqElement, ZqGroup> secondVector;
		private ZqElement y;

		@BeforeEach
		void setUp() {
			n = secureRandom.nextInt(RANDOM_UPPER_BOUND) + 1;
			firstVector = zqGroupGenerator.generateRandomZqElementVector(n);
			secondVector = zqGroupGenerator.generateRandomZqElementVector(n);
			y = ZqElement.create(randomService.genRandomInteger(zqGroup.getQ()), zqGroup);
		}

		@Test
		@DisplayName("with any null parameter throws NullPointerException")
		void starMapNullParams() {
			final SameGroupVector<ZqElement, ZqGroup> emptyVector = SameGroupVector.of();

			assertAll(
					() -> assertThrows(NullPointerException.class, () -> zeroArgumentService.starMap(null, secondVector, y)),
					() -> assertThrows(NullPointerException.class, () -> zeroArgumentService.starMap(firstVector, null, y)),
					() -> assertThrows(NullPointerException.class, () -> zeroArgumentService.starMap(firstVector, secondVector, null)),
					() -> assertThrows(NullPointerException.class, () -> zeroArgumentService.starMap(null, emptyVector, y)),
					() -> assertThrows(NullPointerException.class, () -> zeroArgumentService.starMap(emptyVector, null, y)),
					() -> assertThrows(NullPointerException.class, () -> zeroArgumentService.starMap(emptyVector, emptyVector, null))
			);
		}

		@Test
		@DisplayName("with vectors of different size throws IllegalArgumentException")
		void starMapVectorsDifferentSize() {
			final SameGroupVector<ZqElement, ZqGroup> secondVector = zqGroupGenerator.generateRandomZqElementVector(n + 1);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.starMap(firstVector, secondVector, y));
			assertEquals("The provided vectors must have the same size.", exception.getMessage());

			// With empty vectors.
			final SameGroupVector<ZqElement, ZqGroup> emptyVector = SameGroupVector.of();
			final IllegalArgumentException exceptionSecondEmpty = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.starMap(firstVector, emptyVector, y));
			assertEquals("The provided vectors must have the same size.", exceptionSecondEmpty.getMessage());

			final IllegalArgumentException exceptionFirstEmpty = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.starMap(emptyVector, secondVector, y));
			assertEquals("The provided vectors must have the same size.", exceptionFirstEmpty.getMessage());
		}

		@Test
		@DisplayName("with second vector elements of different group than the first vector throws IllegalArgumentException")
		void starMapVectorsDifferentGroup() {
			// Second vector from different group.
			final ZqGroup otherZqGroup = getDifferentZqGroup();
			final ZqGroupGenerator otherZqGroupGenerator = new ZqGroupGenerator(otherZqGroup);
			final SameGroupVector<ZqElement, ZqGroup> secondVector = otherZqGroupGenerator.generateRandomZqElementVector(n);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.starMap(firstVector, secondVector, y));
			assertEquals("The elements of both vectors must be in the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("constructed with value y from different group throws IllegalArgumentException")
		void starMapYDifferentGroup() {
			// Get another y from a different group.
			final ZqGroup differentZqGroup = getDifferentZqGroup();
			final ZqElement differentGroupY = ZqElement.create(randomService.genRandomInteger(differentZqGroup.getQ()), differentZqGroup);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.starMap(firstVector, secondVector, differentGroupY));
			assertEquals("The value y must be in the same group as the vectors elements", exception.getMessage());
		}

		@Test
		@DisplayName("with empty vectors returns identity")
		void starMapEmptyVectors() {
			final SameGroupVector<ZqElement, ZqGroup> firstVector = SameGroupVector.of();
			final SameGroupVector<ZqElement, ZqGroup> secondVector = SameGroupVector.of();

			assertEquals(zqGroup.getIdentity(), zeroArgumentService.starMap(firstVector, secondVector, y));
		}

		@Test
		@DisplayName("with simple values gives expected result")
		void starMapTestSimpleValues() {
			// Small ZpGroup.
			final ZqGroup group = new ZqGroup(ELEVEN);

			// Construct the two vectors and value y.
			final SameGroupVector<ZqElement, ZqGroup> firstVector = SameGroupVector.of(
					ZqElement.create(TWO, group), ZqElement.create(SIX, group));
			final SameGroupVector<ZqElement, ZqGroup> secondVector = SameGroupVector.of(
					ZqElement.create(THREE, group), ZqElement.create(SEVEN, group));
			final ZqElement y = ZqElement.create(EIGHT, group);

			// Expected starMap result.
			final ZqElement expected = ZqElement.create(EIGHT, group);

			assertEquals(expected, zeroArgumentService.starMap(firstVector, secondVector, y));
		}
	}

	@Nested
	@DisplayName("getZeroArgument")
	class GetZeroArgument {

		private int m;
		private int n;
		private ZeroStatement zeroStatement;
		private ZeroWitness zeroWitness;

		@BeforeEach
		void setUp() {
			ZeroArgumentService zeroArgumentService = new ZeroArgumentService(publicKey, commitmentKey, randomService, hashService);
			ZeroArgumentTestData testData = new ZeroArgumentTestData(commitmentKey, zeroArgumentService);
			zeroStatement = testData.getZeroStatement();
			zeroWitness = testData.getZeroWitness();
			m = testData.getM();
			n = testData.getN();
		}

		@Test
		@DisplayName("with valid statement and witness does not throw")
		void getZeroArgValidStatementAndWitness() {
			// Mock the hashService in order to have a hash value of compatible length (because of small q of test groups).
			final HashService hashServiceMock = mock(HashService.class);
			doReturn(new byte[] { 0x2 }).when(hashServiceMock).recursiveHash(any());

			ZeroArgumentService zeroArgumentService = new ZeroArgumentService(publicKey, commitmentKey, randomService, hashServiceMock);
			ZeroArgumentTestData testData = new ZeroArgumentTestData(commitmentKey, zeroArgumentService);
			ZeroStatement zeroStatement = testData.getZeroStatement();
			ZeroWitness zeroWitness = testData.getZeroWitness();

			final ZeroArgumentService otherZeroArgumentService = testData.getZeroArgumentService();

			assertDoesNotThrow(() -> otherZeroArgumentService.getZeroArgument(zeroStatement, zeroWitness));
		}

		@Test
		@DisplayName("with any null parameter throws NullPointerException")
		void getZeroArgNullParams() {
			assertThrows(NullPointerException.class, () -> zeroArgumentService.getZeroArgument(null, zeroWitness));
			assertThrows(NullPointerException.class, () -> zeroArgumentService.getZeroArgument(zeroStatement, null));
		}

		@Test
		@DisplayName("with commitments and exponents of different size throws IllegalArgumentException ")
		void getZeroArgDiffComExp() {
			// Create another witness with an additional element.
			final SameGroupMatrix<ZqElement, ZqGroup> matrixA = zqGroupGenerator.generateRandomZqElementMatrix(n, m + 1);
			final SameGroupMatrix<ZqElement, ZqGroup> matrixB = zqGroupGenerator.generateRandomZqElementMatrix(n, m + 1);
			final SameGroupVector<ZqElement, ZqGroup> exponentsR = zqGroupGenerator.generateRandomZqElementVector(m + 1);
			final SameGroupVector<ZqElement, ZqGroup> exponentsS = zqGroupGenerator.generateRandomZqElementVector(m + 1);

			final ZeroWitness addElemZeroWitness = new ZeroWitness(matrixA, matrixB, exponentsR, exponentsS);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.getZeroArgument(zeroStatement, addElemZeroWitness));
			assertEquals("The statement commitments must have the same size as the witness exponents.", exception.getMessage());
		}

		@Test
		@DisplayName("with y and exponents of different group throws IllegalArgumentException")
		void getZeroArgDiffGroupYAndExponents() {
			// Create another witness in another group.
			final ZqGroupGenerator otherZqGroupGenerator = new ZqGroupGenerator(getDifferentZqGroup());
			final SameGroupMatrix<ZqElement, ZqGroup> matrixA = otherZqGroupGenerator.generateRandomZqElementMatrix(n, m);
			final SameGroupMatrix<ZqElement, ZqGroup> matrixB = otherZqGroupGenerator.generateRandomZqElementMatrix(n, m);
			final SameGroupVector<ZqElement, ZqGroup> exponentsR = otherZqGroupGenerator.generateRandomZqElementVector(m);
			final SameGroupVector<ZqElement, ZqGroup> exponentsS = otherZqGroupGenerator.generateRandomZqElementVector(m);

			final ZeroWitness otherZqGroupZeroWitness = new ZeroWitness(matrixA, matrixB, exponentsR, exponentsS);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.getZeroArgument(zeroStatement, otherZqGroupZeroWitness));
			assertEquals("The statement y and witness exponents must be part of the same group.", exception.getMessage());

		}

		@Test
		@DisplayName("with Ca commitments not equal to commitment matrix of A throws IllegalArgumentException")
		void getZeroArgDiffCaCommitments() {
			final SameGroupVector<GqElement, GqGroup> commitmentsA = zeroStatement.getCommitmentsA();

			// Generate a different commitment.
			SameGroupVector<GqElement, GqGroup> otherCommitments;
			do {
				otherCommitments = gqGroupGenerator.generateRandomGqElementList(m);
			} while (otherCommitments.equals(commitmentsA));

			final SameGroupVector<GqElement, GqGroup> commitmentsB = zeroStatement.getCommitmentsB();
			final ZeroStatement otherStatement = new ZeroStatement(otherCommitments, commitmentsB, zeroStatement.getY());

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.getZeroArgument(otherStatement, zeroWitness));
			assertEquals("The statement's Ca commitments must be equal to the witness' commitment matrix A.", exception.getMessage());
		}

		@Test
		@DisplayName("with Cb commitments not equal to commitment matrix of B throws IllegalArgumentException")
		void getZeroArgDiffCbCommitments() {
			final SameGroupVector<GqElement, GqGroup> commitmentsB = zeroStatement.getCommitmentsB();

			// Generate a different commitment.
			SameGroupVector<GqElement, GqGroup> otherCommitments;
			do {
				otherCommitments = gqGroupGenerator.generateRandomGqElementList(m);
			} while (otherCommitments.equals(commitmentsB));

			final SameGroupVector<GqElement, GqGroup> commitmentsA = zeroStatement.getCommitmentsA();
			final ZeroStatement otherStatement = new ZeroStatement(commitmentsA, otherCommitments, zeroStatement.getY());

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.getZeroArgument(otherStatement, zeroWitness));
			assertEquals("The statement's Cb commitments must be equal to the witness' commitment matrix B.", exception.getMessage());
		}

		@Test
		@DisplayName("with starMap sum not equal to 0 throws IllegalArgumentException")
		void getZeroArgStarMapNotZero() {
			// Create a simple witness.
			final SameGroupMatrix<ZqElement, ZqGroup> matrixA = SameGroupMatrix
					.fromRows(Collections.singletonList(Collections.singletonList(ZqElement.create(ONE, zqGroup))));
			final SameGroupMatrix<ZqElement, ZqGroup> matrixB = SameGroupMatrix
					.fromRows(Collections.singletonList(Collections.singletonList(ZqElement.create(ONE, zqGroup))));
			final SameGroupVector<ZqElement, ZqGroup> exponentsR = SameGroupVector.of(ZqElement.create(ONE, zqGroup));
			final SameGroupVector<ZqElement, ZqGroup> exponentsS = SameGroupVector.of(ZqElement.create(ONE, zqGroup));
			final ZeroWitness otherWitness = new ZeroWitness(matrixA, matrixB, exponentsR, exponentsS);

			// Derive statement from it.
			final SameGroupVector<GqElement, GqGroup> commitmentsA = CommitmentService
					.getCommitmentMatrix(matrixA, exponentsR, commitmentKey);
			final SameGroupVector<GqElement, GqGroup> commitmentsB = CommitmentService
					.getCommitmentMatrix(matrixB, exponentsS, commitmentKey);
			// Fix y to 1 so the starMap gives 1 (because A and B are 1).
			final ZqElement y = ZqElement.create(ONE, zqGroup);
			final ZeroStatement otherStatement = new ZeroStatement(commitmentsA, commitmentsB, y);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.getZeroArgument(otherStatement, otherWitness));
			assertEquals("The sum of the starMap operations between the witness's matrices columns is not equal to 0.", exception.getMessage());
		}

		@Test
		@DisplayName("with simple values gives expected result")
		void getZeroArgSimpleValues() {
			// Groups.
			final GqGroup simpleGqGroup = new GqGroup(ELEVEN, FIVE, THREE);
			final ZqGroup simpleZqGroup = ZqGroup.sameOrderAs(simpleGqGroup);

			// Statement.
			final SameGroupVector<GqElement, GqGroup> commitmentsA = SameGroupVector.of(
					GqElement.create(FIVE, simpleGqGroup), GqElement.create(THREE, simpleGqGroup), GqElement.create(FOUR, simpleGqGroup));
			final SameGroupVector<GqElement, GqGroup> commitmentsB = SameGroupVector.of(
					GqElement.create(FOUR, simpleGqGroup), GqElement.create(NINE, simpleGqGroup), GqElement.create(NINE, simpleGqGroup));
			final ZqElement y = ZqElement.create(TWO, simpleZqGroup);

			final ZeroStatement simpleZeroStatement = new ZeroStatement(commitmentsA, commitmentsB, y);

			// Witness.
			final SameGroupMatrix<ZqElement, ZqGroup> simpleMatrixA = SameGroupMatrix.fromRows(asList(
					asList(ZqElement.create(TWO, simpleZqGroup), ZqElement.create(ZERO, simpleZqGroup), ZqElement.create(FOUR, simpleZqGroup)),
					asList(ZqElement.create(TWO, simpleZqGroup), ZqElement.create(FOUR, simpleZqGroup), ZqElement.create(FOUR, simpleZqGroup))));
			final SameGroupMatrix<ZqElement, ZqGroup> simpleMatrixB = SameGroupMatrix.fromRows(asList(
					asList(ZqElement.create(THREE, simpleZqGroup), ZqElement.create(TWO, simpleZqGroup), ZqElement.create(ONE, simpleZqGroup)),
					asList(ZqElement.create(ZERO, simpleZqGroup), ZqElement.create(ZERO, simpleZqGroup), ZqElement.create(ZERO, simpleZqGroup))));
			final SameGroupVector<ZqElement, ZqGroup> simpleExponentsR = SameGroupVector.of(
					ZqElement.create(THREE, simpleZqGroup), ZqElement.create(FOUR, simpleZqGroup), ZqElement.create(ZERO, simpleZqGroup));
			final SameGroupVector<ZqElement, ZqGroup> simpleExponentsS = SameGroupVector.of(
					ZqElement.create(ONE, simpleZqGroup), ZqElement.create(TWO, simpleZqGroup), ZqElement.create(FOUR, simpleZqGroup));

			final ZeroWitness simpleZeroWitness = new ZeroWitness(simpleMatrixA, simpleMatrixB, simpleExponentsR, simpleExponentsS);

			// Argument.
			final GqElement cA0 = GqElement.create(FIVE, simpleGqGroup);
			final GqElement cBm = GqElement.create(ONE, simpleGqGroup);
			final SameGroupVector<GqElement, GqGroup> cd = SameGroupVector.of(
					GqElement.create(FOUR, simpleGqGroup), GqElement.create(FOUR, simpleGqGroup), GqElement.create(NINE, simpleGqGroup),
					GqElement.create(NINE, simpleGqGroup), GqElement.create(ONE, simpleGqGroup), GqElement.create(THREE, simpleGqGroup),
					GqElement.create(ONE, simpleGqGroup));
			final SameGroupVector<ZqElement, ZqGroup> aPrime = SameGroupVector.of(
					ZqElement.create(TWO, simpleZqGroup), ZqElement.create(ZERO, simpleZqGroup));
			final SameGroupVector<ZqElement, ZqGroup> bPrime = SameGroupVector.of(
					ZqElement.create(ONE, simpleZqGroup), ZqElement.create(ONE, simpleZqGroup));
			final ZqElement rPrime = ZqElement.create(ONE, simpleZqGroup);
			final ZqElement sPrime = ZqElement.create(FOUR, simpleZqGroup);
			final ZqElement tPrime = ZqElement.create(ONE, simpleZqGroup);

			final ZeroArgument.ZeroArgumentBuilder zeroArgumentBuilder = new ZeroArgument.ZeroArgumentBuilder();
			zeroArgumentBuilder
					.withCA0(cA0)
					.withCBm(cBm)
					.withCd(cd)
					.withAPrime(aPrime)
					.withBPrime(bPrime)
					.withRPrime(rPrime)
					.withSPrime(sPrime)
					.withTPrime(tPrime);
			final ZeroArgument simpleZeroArgument = zeroArgumentBuilder.build();

			// PublicKey and commitmentKey.
			final GqElement h = GqElement.create(NINE, simpleGqGroup);
			final List<GqElement> g = asList(GqElement.create(FOUR, simpleGqGroup), GqElement.create(NINE, simpleGqGroup));
			final CommitmentKey simpleCommitmentKey = new CommitmentKey(h, g);

			final List<GqElement> pkElements = asList(GqElement.create(FOUR, simpleGqGroup), GqElement.create(FOUR, simpleGqGroup));
			final ElGamalMultiRecipientPublicKey simplePublicKey = new ElGamalMultiRecipientPublicKey(pkElements);

			// Mock random elements. There are 13 values to mock:
			// a0=(1,3) bm=(2,1) r0=4 sm=0 t=(0,1,3,4,2,1,2)
			final RandomService randomServiceMock = mock(RandomService.class);
			doReturn(ONE, THREE, TWO, ONE, FOUR, ZERO, ZERO, ONE, THREE, FOUR, TWO, ONE, TWO).when(randomServiceMock)
					.genRandomInteger(simpleZqGroup.getQ());

			// Mock the hashService in order to have a hash value of compatible length (because of small q of test groups).
			final HashService hashServiceMock = mock(HashService.class);
			when(hashServiceMock.recursiveHash(any())).thenReturn(new byte[] { 0x2 });

			final ZeroArgumentService simpleZeroArgumentService = new ZeroArgumentService(simplePublicKey, simpleCommitmentKey, randomServiceMock,
					hashServiceMock);

			// Verification.
			final ZeroArgument zeroArgument = simpleZeroArgumentService.getZeroArgument(simpleZeroStatement, simpleZeroWitness);
			verify(randomServiceMock, times(13)).genRandomInteger(simpleZqGroup.getQ());
			verify(hashServiceMock, times(1)).recursiveHash(any());

			assertEquals(simpleZeroArgument, zeroArgument);
		}

		@Nested
		@DisplayName("VerifyZeroArgument")
		class VerifyZeroArgument {

			@RepeatedTest(10)
			void verifyZeroArgumentTest() {
				// Mock the hashService in order to have a hash value of compatible length (because of small q of test groups).
				final HashService hashServiceMock = mock(HashService.class);
				when(hashServiceMock.recursiveHash(any())).thenReturn(new byte[] { 0x2 });

				ZeroArgumentService zeroArgumentService = new ZeroArgumentService(publicKey, commitmentKey, randomService, hashServiceMock);
				ZeroArgumentTestData testData = new ZeroArgumentTestData(commitmentKey, zeroArgumentService);
				ZeroArgumentService verifyZeroArgumentService = testData.getZeroArgumentService();
				ZeroStatement statement = testData.getZeroStatement();
				ZeroWitness witness = testData.getZeroWitness();

				ZeroArgument zeroArgument = verifyZeroArgumentService.getZeroArgument(statement, witness);

				assertTrue(verifyZeroArgumentService.verifyZeroArgument(statement, zeroArgument));
			}

			@Test
			void testNullInputParameters() {

				ZeroArgument zeroArgument = mock(ZeroArgument.class);
				ZeroStatement zeroStatement = mock(ZeroStatement.class);

				assertThrows(NullPointerException.class, () -> zeroArgumentService.verifyZeroArgument(zeroStatement, null));
				assertThrows(NullPointerException.class, () -> zeroArgumentService.verifyZeroArgument(null, zeroArgument));
			}

			@Test
			void testInputParameterGroupSizes() {

				ZeroArgument zeroArgument = mock(ZeroArgument.class, Mockito.RETURNS_DEEP_STUBS);
				ZeroStatement zeroStatement = mock(ZeroStatement.class, Mockito.RETURNS_DEEP_STUBS);

				when(zeroArgument.getCd().getGroup()).thenReturn(gqGroup);
				when(zeroStatement.getCommitmentsA().getGroup()).thenReturn(gqGroup);

				when(zeroArgument.getCd().size()).thenReturn(1);
				when(zeroStatement.getCommitmentsA().size()).thenReturn(2);

				IllegalArgumentException invalidMException = assertThrows(IllegalArgumentException.class,
						() -> zeroArgumentService.verifyZeroArgument(zeroStatement, zeroArgument));
				assertEquals("The m of the statement should be equal to the m of the argument (2m+1)", invalidMException.getMessage());

			}

			@Test
			void testInputParameterGroupMembership() {

				ZeroArgument zeroArgument = mock(ZeroArgument.class, Mockito.RETURNS_DEEP_STUBS);
				ZeroStatement otherGroupStatement = mock(ZeroStatement.class, Mockito.RETURNS_DEEP_STUBS);

				when(zeroArgument.getCd().getGroup()).thenReturn(gqGroup);
				when(otherGroupStatement.getCommitmentsA().getGroup()).thenReturn(GqGroupTestData.getDifferentGroup(gqGroup));

				IllegalArgumentException wrongGroupException = assertThrows(IllegalArgumentException.class,
						() -> zeroArgumentService.verifyZeroArgument(otherGroupStatement, zeroArgument));
				assertEquals("Statement and argument do not share the same group", wrongGroupException.getMessage());

			}

		}

	}
	// ===============================================================================================================================================
	// Utility methods
	// ===============================================================================================================================================

	/**
	 * Get a different ZqGroup from the one used before each test cases.
	 *
	 * @return a different {@link ZqGroup}.
	 */
	private ZqGroup getDifferentZqGroup() {
		GqGroup otherGqGroup;
		ZqGroup otherZqGroup;
		do {
			otherGqGroup = GqGroupTestData.getGroup();
			otherZqGroup = ZqGroup.sameOrderAs(otherGqGroup);
		} while (otherZqGroup.equals(zqGroup));

		return otherZqGroup;
	}
}
