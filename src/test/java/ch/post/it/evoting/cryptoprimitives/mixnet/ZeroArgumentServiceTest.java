/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
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
	private static final BigInteger ELEVEN = BigInteger.valueOf(11);
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
		final List<GqElement> g = Stream.generate(gqGroupGenerator::genNonIdentityNonGeneratorMember).limit(10).collect(Collectors.toList());
		commitmentKey = new CommitmentKey(h, g);

		final List<GqElement> pkElements = Stream.generate(gqGroupGenerator::genNonIdentityNonGeneratorMember).limit(10).collect(Collectors.toList());
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
		final List<GqElement> pkElements = Stream.generate(otherGqGroupGenerator::genNonIdentityNonGeneratorMember).limit(10)
				.collect(Collectors.toList());
		final ElGamalMultiRecipientPublicKey otherPublicKey = new ElGamalMultiRecipientPublicKey(pkElements);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ZeroArgumentService(otherPublicKey, commitmentKey, randomService, hashService));
		assertEquals("The public and commitment keys are not from the same group.", exception.getMessage());
	}

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

	@Nested
	@DisplayName("computeDVector")
	class ComputeDVectorTest {

		private int m;
		private int n;
		private List<List<ZqElement>> firstMatrix;
		private List<List<ZqElement>> secondMatrix;
		private ZqElement y;

		@BeforeEach
		void setUp() {
			m = secureRandom.nextInt(10) + 1;
			n = secureRandom.nextInt(10) + 1;
			firstMatrix = zqGroupGenerator.generateRandomZqElementMatrix(n, m + 1);
			secondMatrix = zqGroupGenerator.generateRandomZqElementMatrix(n, m + 1);
			y = ZqElement.create(randomService.genRandomInteger(zqGroup.getQ()), zqGroup);
		}

		@Test
		@DisplayName("with any null parameter throws NullPointerException")
		void computeDVectorNullParams() {
			final List<List<ZqElement>> emptyMatrix = Collections.emptyList();

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
		@DisplayName("with matrices having null rows throws IllegalArgumentException")
		void computeDVectorNullRows() {
			final List<List<ZqElement>> nullRowFirstMatrix = zqGroupGenerator.generateRandomZqElementMatrix(m + 1, n);
			nullRowFirstMatrix.set(m, null);
			final IllegalArgumentException exceptionFirst = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.computeDVector(nullRowFirstMatrix, secondMatrix, y));
			assertEquals("First matrix rows must not be null.", exceptionFirst.getMessage());

			final List<List<ZqElement>> nullRowSecondMatrix = zqGroupGenerator.generateRandomZqElementMatrix(m + 1, n);
			nullRowSecondMatrix.set(m, null);
			final IllegalArgumentException exceptionSecond = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.computeDVector(firstMatrix, nullRowSecondMatrix, y));
			assertEquals("Second matrix rows must not be null.", exceptionSecond.getMessage());
		}

		@Test
		@DisplayName("with matrices having null elements throws IllegalArgumentException")
		void computeDVectorNullElements() {
			final List<List<ZqElement>> nullElemFirstMatrix = zqGroupGenerator.generateRandomZqElementMatrix(m + 1, n);
			nullElemFirstMatrix.get(m).set(0, null);
			final IllegalArgumentException exceptionFirst = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.computeDVector(nullElemFirstMatrix, secondMatrix, y));
			assertEquals("First matrix elements must not be null.", exceptionFirst.getMessage());

			final List<List<ZqElement>> nullElemSecondMatrix = zqGroupGenerator.generateRandomZqElementMatrix(m + 1, n);
			nullElemSecondMatrix.get(m).set(0, null);
			final IllegalArgumentException exceptionSecond = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.computeDVector(firstMatrix, nullElemSecondMatrix, y));
			assertEquals("Second matrix elements must not be null.", exceptionSecond.getMessage());
		}

		@Test
		@DisplayName("with matrices having unequal number of lines throws IllegalArgumentException")
		void computeDVectorDifferentSizeLines() {
			// Add an additional line to first matrix.
			final List<ZqElement> additionalLine = zqGroupGenerator.generateRandomZqElementList(m + 1);
			firstMatrix.add(additionalLine);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.computeDVector(firstMatrix, secondMatrix, y));
			assertEquals("The two matrices must have the same number of rows.", exception.getMessage());

			// With empty matrices.
			final List<List<ZqElement>> emptyMatrix = Collections.emptyList();
			final IllegalArgumentException exceptionSecondEmpty = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.computeDVector(firstMatrix, emptyMatrix, y));
			assertEquals("The two matrices must have the same number of rows.", exceptionSecondEmpty.getMessage());

			final IllegalArgumentException exceptionFirstEmpty = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.computeDVector(emptyMatrix, secondMatrix, y));
			assertEquals("The two matrices must have the same number of rows.", exceptionFirstEmpty.getMessage());
		}

		@Test
		@DisplayName("with first matrix having columns of different size throws IllegalArgumentException")
		void computeDVectorFirstMatrixDifferentColumnSize() {
			// Add an additional line to first matrix with less elements in the column.
			final List<ZqElement> lineWithSmallerColumn = zqGroupGenerator.generateRandomZqElementList(0);
			firstMatrix.add(lineWithSmallerColumn);

			// Also add additional line to second matrix to have same number of lines.
			final List<ZqElement> additionalLine = zqGroupGenerator.generateRandomZqElementList(n);
			secondMatrix.add(additionalLine);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.computeDVector(firstMatrix, secondMatrix, y));
			assertEquals("All rows of the matrix must have the same number of columns.", exception.getMessage());
		}

		@Test
		@DisplayName("with second matrix having columns of different size throws IllegalArgumentException")
		void computeDVectorSecondMatrixDifferentColumnSize() {
			// Add an additional line to second matrix with less elements in the column.
			final List<ZqElement> lineWithSmallerColumn = zqGroupGenerator.generateRandomZqElementList(0);
			secondMatrix.add(lineWithSmallerColumn);

			// Also add additional line to first matrix to have same number of lines.
			final List<ZqElement> additionalLine = zqGroupGenerator.generateRandomZqElementList(n);
			firstMatrix.add(additionalLine);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.computeDVector(firstMatrix, secondMatrix, y));
			assertEquals("All rows of the matrix must have the same number of columns.", exception.getMessage());
		}

		@Test
		@DisplayName("with matrices with different number of columns throws IllegalArgumentException")
		void computeDVectorDifferentSizeColumns() {
			final List<List<ZqElement>> otherFirstMatrix = zqGroupGenerator.generateRandomZqElementMatrix(m, n);
			final List<List<ZqElement>> otherSecondMatrix = zqGroupGenerator.generateRandomZqElementMatrix(m, n + 1);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.computeDVector(otherFirstMatrix, otherSecondMatrix, y));
			assertEquals("The two matrices must have the same number of columns.", exception.getMessage());
		}

		@Test
		@DisplayName("with first matrix having elements of different groups throws IllegalArgumentException")
		void computeDVectorFirstMatrixDifferentGroup() {
			// Get a different ZqGroup.
			final ZqGroup otherZqGroup = getDifferentZqGroup();
			final ZqGroupGenerator otherZqGroupGenerator = new ZqGroupGenerator(otherZqGroup);

			// Add an additional line to first matrix with elements from a different group.
			final List<ZqElement> differentGroupElements = otherZqGroupGenerator.generateRandomZqElementList(m + 1);
			firstMatrix.add(differentGroupElements);

			// Also add additional line to second matrix but from same group.
			final List<ZqElement> sameGroupElements = zqGroupGenerator.generateRandomZqElementList(m + 1);
			secondMatrix.add(sameGroupElements);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.computeDVector(firstMatrix, secondMatrix, y));
			assertEquals("All elements of the matrix must be in the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("with second matrix having elements of different groups throws IllegalArgumentException")
		void computeDVectorSecondMatrixDifferentGroup() {
			// Get a different ZqGroup.
			final ZqGroup otherZqGroup = getDifferentZqGroup();
			final ZqGroupGenerator otherZqGroupGenerator = new ZqGroupGenerator(otherZqGroup);

			// Add an additional line to second matrix with elements from a different group.
			final List<ZqElement> differentGroupElements = otherZqGroupGenerator.generateRandomZqElementList(m + 1);
			secondMatrix.add(differentGroupElements);

			// Also add additional line to fist matrix but from same group.
			final List<ZqElement> sameGroupElements = zqGroupGenerator.generateRandomZqElementList(m + 1);
			firstMatrix.add(sameGroupElements);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.computeDVector(firstMatrix, secondMatrix, y));
			assertEquals("All elements of the matrix must be in the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("with second matrix having elements of different group than the first matrix throws IllegalArgumentException")
		void computeDVectorMatricesDifferentGroup() {
			// Get a second matrix in a different ZqGroup.
			final ZqGroup otherZqGroup = getDifferentZqGroup();
			final ZqGroupGenerator otherZqGroupGenerator = new ZqGroupGenerator(otherZqGroup);
			final List<List<ZqElement>> differentGroupSecondMatrix = otherZqGroupGenerator.generateRandomZqElementMatrix(n, m + 1);

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
			final List<ZqElement> emptyD = Collections.emptyList();
			final List<List<ZqElement>> firstEmptyMatrix = Collections.emptyList();
			final List<List<ZqElement>> secondEmptyMatrix = Collections.emptyList();

			assertEquals(emptyD, zeroArgumentService.computeDVector(firstEmptyMatrix, secondEmptyMatrix, y));
		}

		@Test
		@DisplayName("with matrices with empty columns gives empty result vector")
		void computeDVectorEmptyColumns() {
			final List<ZqElement> emptyD = Collections.emptyList();
			final List<List<ZqElement>> firstEmptyMatrix = Collections.singletonList(Collections.emptyList());
			final List<List<ZqElement>> secondEmptyMatrix = Collections.singletonList(Collections.emptyList());

			assertEquals(emptyD, zeroArgumentService.computeDVector(firstEmptyMatrix, secondEmptyMatrix, y));
		}

		@Test
		@DisplayName("with simple values gives expected result")
		void computeDVectorSimpleValuesTest() {
			// Small Zq group.
			final ZqGroup group = new ZqGroup(ELEVEN);

			// Construct the two matrices and value y.
			final List<ZqElement> a0 = Arrays.asList(ZqElement.create(ZERO, group), ZqElement.create(TWO, group));
			final List<ZqElement> a1 = Arrays.asList(ZqElement.create(FOUR, group), ZqElement.create(SIX, group));
			final List<ZqElement> b0 = Arrays.asList(ZqElement.create(ONE, group), ZqElement.create(THREE, group));
			final List<ZqElement> b1 = Arrays.asList(ZqElement.create(FIVE, group), ZqElement.create(SEVEN, group));
			final List<List<ZqElement>> firstMatrix = Arrays.asList(a0, a1);
			final List<List<ZqElement>> secondMatrix = Arrays.asList(b0, b1);
			final ZqElement y = ZqElement.create(EIGHT, group);

			// Expected d vector.
			final List<ZqElement> expected = Arrays
					.asList(ZqElement.create(FOUR, group), ZqElement.create(SEVEN, group), ZqElement.create(ZERO, group));

			assertEquals(expected, zeroArgumentService.computeDVector(firstMatrix, secondMatrix, y));
		}
	}

	@Nested
	@DisplayName("starMap")
	class StarMapTest {

		private int n;
		private List<ZqElement> firstVector;
		private List<ZqElement> secondVector;
		private ZqElement y;

		@BeforeEach
		void setUp() {
			n = secureRandom.nextInt(10) + 1;
			firstVector = zqGroupGenerator.generateRandomZqElementList(n);
			secondVector = zqGroupGenerator.generateRandomZqElementList(n);
			y = ZqElement.create(randomService.genRandomInteger(zqGroup.getQ()), zqGroup);
		}

		@Test
		@DisplayName("with any null parameter throws NullPointerException")
		void starMapNullParams() {
			final List<ZqElement> emptyVector = Collections.emptyList();

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
		@DisplayName("with vector having a null element throws IllegalArgumentException")
		void starMapNullElements() {
			final List<ZqElement> nullElemFirstVector = zqGroupGenerator.generateRandomZqElementList(n);
			nullElemFirstVector.set(0, null);
			final List<ZqElement> nullElemSecondVector = zqGroupGenerator.generateRandomZqElementList(n);
			nullElemSecondVector.set(0, null);

			final IllegalArgumentException exceptionFirst = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.starMap(nullElemFirstVector, secondVector, y));
			assertEquals("The elements of the first vector must not be null.", exceptionFirst.getMessage());

			final IllegalArgumentException exceptionSecond = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.starMap(firstVector, nullElemSecondVector, y));
			assertEquals("The elements of the second vector must not be null.", exceptionSecond.getMessage());
		}

		@Test
		@DisplayName("with vectors of different size throws IllegalArgumentException")
		void starMapVectorsDifferentSize() {
			final List<ZqElement> secondVector = zqGroupGenerator.generateRandomZqElementList(n + 1);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.starMap(firstVector, secondVector, y));
			assertEquals("The provided vectors must have the same size.", exception.getMessage());

			// With empty vectors.
			final List<ZqElement> emptyVector = Collections.emptyList();
			final IllegalArgumentException exceptionSecondEmpty = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.starMap(firstVector, emptyVector, y));
			assertEquals("The provided vectors must have the same size.", exceptionSecondEmpty.getMessage());

			final IllegalArgumentException exceptionFirstEmpty = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.starMap(emptyVector, secondVector, y));
			assertEquals("The provided vectors must have the same size.", exceptionFirstEmpty.getMessage());
		}

		@Test
		@DisplayName("with first vector having different group elements throws IllegalArgumentException")
		void starMapFirstVectorDifferentGroup() {
			final List<ZqElement> secondVector = zqGroupGenerator.generateRandomZqElementList(n + 1);

			// Add an element from a different group to first vector.
			final ZqGroup differentZqGroup = getDifferentZqGroup();
			firstVector.add(ZqElement.create(randomService.genRandomInteger(differentZqGroup.getQ()), differentZqGroup));

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.starMap(firstVector, secondVector, y));
			assertEquals("All elements must belong to the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("with second vector having different group elements throws IllegalArgumentException")
		void starMapSecondVectorDifferentGroup() {
			final List<ZqElement> firstVector = zqGroupGenerator.generateRandomZqElementList(n + 1);

			// Add an element from a different group to second vector.
			final ZqGroup differentZqGroup = getDifferentZqGroup();
			secondVector.add(ZqElement.create(randomService.genRandomInteger(differentZqGroup.getQ()), differentZqGroup));

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.starMap(firstVector, secondVector, y));
			assertEquals("All elements must belong to the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("with second vector elements of different group than the first vector throws IllegalArgumentException")
		void starMapVectorsDifferentGroup() {
			// Second vector from different group.
			final ZqGroup otherZqGroup = getDifferentZqGroup();
			final ZqGroupGenerator otherZqGroupGenerator = new ZqGroupGenerator(otherZqGroup);
			final List<ZqElement> secondVector = otherZqGroupGenerator.generateRandomZqElementList(n);

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
			final List<ZqElement> firstVector = Collections.emptyList();
			final List<ZqElement> secondVector = Collections.emptyList();

			assertEquals(zqGroup.getIdentity(), zeroArgumentService.starMap(firstVector, secondVector, y));
		}

		@Test
		@DisplayName("with simple values gives expected result")
		void starMapTestSimpleValues() {
			// Small ZpGroup.
			final ZqGroup group = new ZqGroup(ELEVEN);

			// Construct the two vectors and value y.
			final List<ZqElement> firstVector = Arrays.asList(ZqElement.create(TWO, group), ZqElement.create(SIX, group));
			final List<ZqElement> secondVector = Arrays.asList(ZqElement.create(THREE, group), ZqElement.create(SEVEN, group));
			final ZqElement y = ZqElement.create(EIGHT, group);

			// Expected starMap result.
			final ZqElement expected = ZqElement.create(ONE, group);

			assertEquals(expected, zeroArgumentService.starMap(firstVector, secondVector, y));
		}
	}

	// ===============================================================================================================================================
	// Utility methods
	// ===============================================================================================================================================

	@Nested
	@DisplayName("getZeroArgument")
	class GetZeroArgument {

		private int m;
		private int n;
		private ZeroStatement zeroStatement;
		private ZeroWitness zeroWitness;

		@BeforeEach
		void setUp() {
			m = secureRandom.nextInt(10) + 1; // Columns.
			n = secureRandom.nextInt(10) + 1; // Rows.

			// Construct valid witness and statement. To do so, pick at random every witness parameters and the witness' y value. Then isolate the
			// last element of matrix B, B_(n,m) in the starMap ensure equation. Once done, try every member of the Zq group as a value for B_(n,m)
			// until the starMap ensure equation is satisfied. This is fast as long as the test groups are small.
			List<List<ZqElement>> matrixA;
			List<List<ZqElement>> matrixB;
			final List<ZqElement> exponentsR = zqGroupGenerator.generateRandomZqElementList(m);
			final List<ZqElement> exponentsS = zqGroupGenerator.generateRandomZqElementList(m);
			ZqElement y;

			// Generate a new set of random values until a valid B_(n,m) is found.
			Optional<ZqElement> matrixBLastElem;
			do {
				matrixA = zqGroupGenerator.generateRandomZqElementMatrix(n, m);
				matrixB = zqGroupGenerator.generateRandomZqElementMatrix(n, m);
				y = ZqElement.create(randomService.genRandomInteger(zqGroup.getQ()), zqGroup);

				// Copies to be usable in streams.
				final SameGroupMatrix<ZqElement, ZqGroup> finalMatrixA = SameGroupMatrix.fromRows(matrixA);
				final SameGroupMatrix<ZqElement, ZqGroup> finalMatrixB = SameGroupMatrix.fromRows(matrixB);
				ZqElement finalY = y;

				final ZqElement firstRight = IntStream.range(0, m - 1)
						.mapToObj(i -> zeroArgumentService.starMap(finalMatrixA.getColumn(i), finalMatrixB.getColumn(i), finalY))
						.reduce(zqGroup.getIdentity(), ZqElement::add).negate();
				final ZqElement secondRight = IntStream.range(0, n - 1)
						.mapToObj(j -> finalMatrixA.get(j, m - 1)
								.multiply(finalMatrixB.get(j, m - 1))
								.multiply(finalY.exponentiate(BigInteger.valueOf(j))))
						.reduce(zqGroup.getIdentity(), ZqElement::add).negate();
				final ZqElement right = firstRight.add(secondRight);

				matrixBLastElem = IntStream.range(0, zqGroup.getQ().intValue())
						.mapToObj(i -> ZqElement.create(BigInteger.valueOf(i), zqGroup))
						.filter(x -> finalMatrixA.get(n - 1, m - 1)
								.multiply(x)
								.multiply(finalY.exponentiate(BigInteger.valueOf(n - 1)))
								.equals(right))
						.findAny();
			} while (!matrixBLastElem.isPresent());

			// Replace B_(n,m) by the value satisfying the ensure equation.
			matrixB.get(n - 1).set(m - 1, matrixBLastElem.get());

			// Construct the remaining parts of the statement.
			final List<GqElement> commitmentsCa = CommitmentService
					.getCommitmentMatrix(SameGroupMatrix.fromRows(matrixA), new SameGroupVector<>(exponentsR), commitmentKey);
			final List<GqElement> commitmentsCb = CommitmentService
					.getCommitmentMatrix(SameGroupMatrix.fromRows(matrixB), new SameGroupVector<>(exponentsS), commitmentKey);

			zeroStatement = new ZeroStatement(commitmentsCa, commitmentsCb, y);
			zeroWitness = new ZeroWitness(matrixA, matrixB, exponentsR, exponentsS);
		}

		@Test
		@DisplayName("with valid statement and witness does not throw")
		void getZeroArgValidStatementAndWitness() {
			// Mock the hashService in order to have a hash value of compatible length (because of small q of test groups).
			final HashService hashServiceMock = mock(HashService.class);
			doReturn(new byte[] { 0x2 }).when(hashServiceMock).recursiveHash(any());

			final ZeroArgumentService otherZeroArgumentService = new ZeroArgumentService(publicKey, commitmentKey, randomService,
					hashServiceMock);

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
			final List<List<ZqElement>> matrixA = zqGroupGenerator.generateRandomZqElementMatrix(n, m + 1);
			final List<List<ZqElement>> matrixB = zqGroupGenerator.generateRandomZqElementMatrix(n, m + 1);
			final List<ZqElement> exponentsR = zqGroupGenerator.generateRandomZqElementList(m + 1);
			final List<ZqElement> exponentsS = zqGroupGenerator.generateRandomZqElementList(m + 1);

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
			final List<List<ZqElement>> matrixA = otherZqGroupGenerator.generateRandomZqElementMatrix(n, m);
			final List<List<ZqElement>> matrixB = otherZqGroupGenerator.generateRandomZqElementMatrix(n, m);
			final List<ZqElement> exponentsR = otherZqGroupGenerator.generateRandomZqElementList(m);
			final List<ZqElement> exponentsS = otherZqGroupGenerator.generateRandomZqElementList(m);

			final ZeroWitness otherZqGroupZeroWitness = new ZeroWitness(matrixA, matrixB, exponentsR, exponentsS);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.getZeroArgument(zeroStatement, otherZqGroupZeroWitness));
			assertEquals("The statement y and exponents must be part of the same group.", exception.getMessage());

		}

		@Test
		@DisplayName("with Ca commitments not equal to commitment matrix of A throws IllegalArgumentException")
		void getZeroArgDiffCaCommitments() {
			final List<GqElement> commitmentsA = zeroStatement.getCommitmentsA().stream().collect(Collectors.toList());

			// Generate a different commitment.
			List<GqElement> otherCommitments;
			do {
				otherCommitments = gqGroupGenerator.generateRandomGqElementList(m);
			} while (otherCommitments.equals(commitmentsA));

			final List<GqElement> commitmentsB = zeroStatement.getCommitmentsB().stream().collect(Collectors.toList());
			final ZeroStatement otherStatement = new ZeroStatement(otherCommitments, commitmentsB, zeroStatement.getY());

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.getZeroArgument(otherStatement, zeroWitness));
			assertEquals("The statement's Ca commitments must be equal to the witness' commitment matrix A.", exception.getMessage());
		}

		@Test
		@DisplayName("with Cb commitments not equal to commitment matrix of B throws IllegalArgumentException")
		void getZeroArgDiffCbCommitments() {
			final List<GqElement> commitmentsB = zeroStatement.getCommitmentsB().stream().collect(Collectors.toList());

			// Generate a different commitment.
			List<GqElement> otherCommitments;
			do {
				otherCommitments = gqGroupGenerator.generateRandomGqElementList(m);
			} while (otherCommitments.equals(commitmentsB));

			final List<GqElement> commitmentsA = zeroStatement.getCommitmentsA().stream().collect(Collectors.toList());
			final ZeroStatement otherStatement = new ZeroStatement(commitmentsA, otherCommitments, zeroStatement.getY());

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.getZeroArgument(otherStatement, zeroWitness));
			assertEquals("The statement's Cb commitments must be equal to the witness' commitment matrix B.", exception.getMessage());
		}

		@Test
		@DisplayName("with starMap sum not equal to 0 throws IllegalArgumentException")
		void getZeroArgStarMapNotZero() {
			// Create a simple witness.
			final List<List<ZqElement>> matrixA = Collections.singletonList(Collections.singletonList(ZqElement.create(ONE, zqGroup)));
			final List<List<ZqElement>> matrixB = Collections.singletonList(Collections.singletonList(ZqElement.create(ONE, zqGroup)));
			final List<ZqElement> exponentsR = Collections.singletonList(ZqElement.create(ONE, zqGroup));
			final List<ZqElement> exponentsS = Collections.singletonList(ZqElement.create(ONE, zqGroup));
			final ZeroWitness otherWitness = new ZeroWitness(matrixA, matrixB, exponentsR, exponentsS);

			// Derive statement from it.
			final List<GqElement> commitmentsA = CommitmentService
					.getCommitmentMatrix(SameGroupMatrix.fromRows(matrixA), new SameGroupVector<>(exponentsR), commitmentKey);
			final List<GqElement> commitmentsB = CommitmentService
					.getCommitmentMatrix(SameGroupMatrix.fromRows(matrixB), new SameGroupVector<>(exponentsS), commitmentKey);
			// Fix y to 1 so the starMap gives 1 (because A and B are 1).
			final ZqElement y = ZqElement.create(ONE, zqGroup);
			final ZeroStatement otherStatement = new ZeroStatement(commitmentsA, commitmentsB, y);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.getZeroArgument(otherStatement, otherWitness));
			assertEquals("The starMap sum between the witness' matrices rows are not equal to ZqGroup identity.", exception.getMessage());
		}

		@Test
		@DisplayName("with simple values gives expected result")
		void getZeroArgSimpleValues() {
			// Groups.
			final GqGroup simpleGqGroup = new GqGroup(ELEVEN, FIVE, THREE);
			final ZqGroup simpleZqGroup = ZqGroup.sameOrderAs(simpleGqGroup);

			// Statement.
			final List<GqElement> commitmentsA = Arrays.asList(GqElement.create(ONE, simpleGqGroup), GqElement.create(ONE, simpleGqGroup));
			final List<GqElement> commitmentsB = Arrays.asList(GqElement.create(NINE, simpleGqGroup), GqElement.create(FIVE, simpleGqGroup));
			final ZqElement y = ZqElement.create(FOUR, simpleZqGroup);

			final ZeroStatement simpleZeroStatement = new ZeroStatement(commitmentsA, commitmentsB, y);

			// Witness.
			final List<List<ZqElement>> simpleMatrixA = Arrays.asList(
					Arrays.asList(ZqElement.create(ONE, simpleZqGroup), ZqElement.create(TWO, simpleZqGroup)),
					Arrays.asList(ZqElement.create(TWO, simpleZqGroup), ZqElement.create(TWO, simpleZqGroup)));
			final List<List<ZqElement>> simpleMatrixB = Arrays.asList(
					Arrays.asList(ZqElement.create(THREE, simpleZqGroup), ZqElement.create(ONE, simpleZqGroup)),
					Arrays.asList(ZqElement.create(ZERO, simpleZqGroup), ZqElement.create(ZERO, simpleZqGroup)));
			final List<ZqElement> simpleExponentsR = Arrays.asList(ZqElement.create(ZERO, simpleZqGroup), ZqElement.create(FOUR, simpleZqGroup));
			final List<ZqElement> simpleExponentsS = Arrays.asList(ZqElement.create(ZERO, simpleZqGroup), ZqElement.create(ONE, simpleZqGroup));

			final ZeroWitness simpleZeroWitness = new ZeroWitness(simpleMatrixA, simpleMatrixB, simpleExponentsR, simpleExponentsS);

			// Argument.
			final GqElement cA0 = GqElement.create(FOUR, simpleGqGroup);
			final GqElement cBm = GqElement.create(NINE, simpleGqGroup);
			final List<GqElement> cd = Arrays
					.asList(GqElement.create(NINE, simpleGqGroup), GqElement.create(NINE, simpleGqGroup), GqElement.create(FOUR, simpleGqGroup),
							GqElement.create(ONE, simpleGqGroup), GqElement.create(NINE, simpleGqGroup));
			final List<ZqElement> aPrime = Arrays.asList(ZqElement.create(THREE, simpleZqGroup), ZqElement.create(ONE, simpleZqGroup));
			final List<ZqElement> bPrime = Arrays.asList(ZqElement.create(TWO, simpleZqGroup), ZqElement.create(THREE, simpleZqGroup));
			final ZqElement rPrime = ZqElement.create(ONE, simpleZqGroup);
			final ZqElement sPrime = ZqElement.create(ONE, simpleZqGroup);
			final ZqElement tPrime = ZqElement.create(THREE, simpleZqGroup);

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
			final GqElement h = GqElement.create(FOUR, simpleGqGroup);
			final List<GqElement> g = Arrays.asList(GqElement.create(FOUR, simpleGqGroup), GqElement.create(FIVE, simpleGqGroup));
			final CommitmentKey simpleCommitmentKey = new CommitmentKey(h, g);

			final List<GqElement> pkElements = Arrays.asList(GqElement.create(NINE, simpleGqGroup), GqElement.create(FIVE, simpleGqGroup));
			final ElGamalMultiRecipientPublicKey simplePublicKey = new ElGamalMultiRecipientPublicKey(pkElements);

			// Mock random elements. There are 11 values to mock:
			// a0=(3,4) bm=(3,3) r0=0 sm=4 t=(1,3,1,0,2)
			final RandomService randomServiceMock = mock(RandomService.class);
			doReturn(THREE, FOUR, THREE, THREE, ZERO, FOUR, ONE, THREE, ONE, ZERO, TWO).when(randomServiceMock)
					.genRandomInteger(simpleZqGroup.getQ());

			// Mock the hashService in order to have a hash value of compatible length (because of small q of test groups).
			final HashService hashServiceMock = mock(HashService.class);
			doReturn(new byte[] { 0x2 }).when(hashServiceMock).recursiveHash(any());

			final ZeroArgumentService simpleZeroArgumentService = new ZeroArgumentService(simplePublicKey, simpleCommitmentKey,
					randomServiceMock, hashServiceMock);

			// Verification.
			final ZeroArgument zeroArgument = simpleZeroArgumentService.getZeroArgument(simpleZeroStatement, simpleZeroWitness);
			verify(randomServiceMock, times(11)).genRandomInteger(simpleZqGroup.getQ());
			verify(hashServiceMock, times(1)).recursiveHash(any());

			assertEquals(simpleZeroArgument, zeroArgument);
		}
	}
}
