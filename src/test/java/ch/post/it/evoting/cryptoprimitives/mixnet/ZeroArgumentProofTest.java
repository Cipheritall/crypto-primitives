/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static ch.post.it.evoting.cryptoprimitives.test.tools.generator.HasGroupElementGenerator.generateElementList;
import static ch.post.it.evoting.cryptoprimitives.test.tools.generator.HasGroupElementGenerator.generateElementMatrix;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GqGroupTestData;

class ZeroArgumentProofTest {

	private static final BigInteger ZERO = BigInteger.valueOf(0);
	private static final BigInteger ONE = BigInteger.valueOf(1);
	private static final BigInteger TWO = BigInteger.valueOf(2);
	private static final BigInteger THREE = BigInteger.valueOf(3);
	private static final BigInteger FOUR = BigInteger.valueOf(4);
	private static final BigInteger FIVE = BigInteger.valueOf(5);
	private static final BigInteger SIX = BigInteger.valueOf(6);
	private static final BigInteger SEVEN = BigInteger.valueOf(7);
	private static final BigInteger EIGHT = BigInteger.valueOf(8);
	private static final BigInteger ELEVEN = BigInteger.valueOf(11);

	private final RandomService randomService = new RandomService();
	private final SecureRandom secureRandom = new SecureRandom();

	private ZqGroup zqGroup;
	private ZeroArgumentProof zeroArgumentProof;

	@BeforeEach
	void setup() {
		final GqGroup gqGroup = GqGroupTestData.getGroup();
		zqGroup = ZqGroup.sameOrderAs(gqGroup);
		final ZqElement y = ZqElement.create(randomService.genRandomInteger(zqGroup.getQ()), zqGroup);
		zeroArgumentProof = new ZeroArgumentProof(y);
	}

	@Test
	@DisplayName("construct with a null y value throws NullPointerException")
	void constructorNullY() {
		assertThrows(NullPointerException.class, () -> new ZeroArgumentProof(null));
	}

	@Nested
	@DisplayName("computeDVector")
	class ComputeDVectorTest {

		private int m;
		private int n;
		private List<List<ZqElement>> firstMatrix;
		private List<List<ZqElement>> secondMatrix;

		@BeforeEach
		void setUp() {
			m = secureRandom.nextInt(10) + 1;
			n = secureRandom.nextInt(10) + 1;
			firstMatrix = generateRandomZqElementMatrix(n, m + 1, zqGroup);
			secondMatrix = generateRandomZqElementMatrix(n, m + 1, zqGroup);
		}

		@Test
		@DisplayName("constructed with y from a different group throws IllegalArgumentException")
		void computeDVectorYDifferentGroup() {
			// Get a different ZqGroup.
			final ZqGroup differentZqGroup = getDifferentZqGroup();

			// Create a y value from a different group.
			final ZqElement differentGroupY = ZqElement.create(randomService.genRandomInteger(differentZqGroup.getQ()), differentZqGroup);

			// Construct with different y.
			zeroArgumentProof = new ZeroArgumentProof(differentGroupY);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentProof.computeDVector(firstMatrix, secondMatrix));
			assertEquals("The value y must be in the same group as the elements of the matrices.", exception.getMessage());
		}

		@Test
		@DisplayName("with any null parameter throws NullPointerException")
		void computeDVectorNullParams() {
			final List<List<ZqElement>> emptyMatrix = Collections.emptyList();

			assertAll(
					() -> assertThrows(NullPointerException.class, () -> zeroArgumentProof.computeDVector(null, secondMatrix)),
					() -> assertThrows(NullPointerException.class, () -> zeroArgumentProof.computeDVector(null, emptyMatrix)),
					() -> assertThrows(NullPointerException.class, () -> zeroArgumentProof.computeDVector(firstMatrix, null)),
					() -> assertThrows(NullPointerException.class, () -> zeroArgumentProof.computeDVector(emptyMatrix, null))
			);
		}

		@Test
		@DisplayName("with matrices having null rows throws IllegalArgumentException")
		void computeDVectorNullRows() {
			final List<List<ZqElement>> nullRowFirstMatrix = generateRandomZqElementMatrix(m + 1, n, zqGroup);
			nullRowFirstMatrix.set(m, null);
			final IllegalArgumentException exceptionFirst = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentProof.computeDVector(nullRowFirstMatrix, secondMatrix));
			assertEquals("First matrix rows must not be null.", exceptionFirst.getMessage());

			final List<List<ZqElement>> nullRowSecondMatrix = generateRandomZqElementMatrix(m + 1, n, zqGroup);
			nullRowSecondMatrix.set(m, null);
			final IllegalArgumentException exceptionSecond = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentProof.computeDVector(firstMatrix, nullRowSecondMatrix));
			assertEquals("Second matrix rows must not be null.", exceptionSecond.getMessage());
		}

		@Test
		@DisplayName("with matrices having null elements throws IllegalArgumentException")
		void computeDVectorNullElements() {
			final List<List<ZqElement>> nullElemFirstMatrix = generateRandomZqElementMatrix(m + 1, n, zqGroup);
			nullElemFirstMatrix.get(m).set(0, null);
			final IllegalArgumentException exceptionFirst = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentProof.computeDVector(nullElemFirstMatrix, secondMatrix));
			assertEquals("First matrix elements must be not be null.", exceptionFirst.getMessage());

			final List<List<ZqElement>> nullElemSecondMatrix = generateRandomZqElementMatrix(m + 1, n, zqGroup);
			nullElemSecondMatrix.get(m).set(0, null);
			final IllegalArgumentException exceptionSecond = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentProof.computeDVector(firstMatrix, nullElemSecondMatrix));
			assertEquals("Second matrix elements must be not be null.", exceptionSecond.getMessage());
		}

		@Test
		@DisplayName("with matrices with not same number of lines throws IllegalArgumentException")
		void computeDVectorDifferentSizeLines() {
			// Add an additional line to first matrix.
			final List<ZqElement> additionalLine = generateRandomZqElementList(m + 1, zqGroup);
			firstMatrix.add(additionalLine);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentProof.computeDVector(firstMatrix, secondMatrix));
			assertEquals("The two matrices must have the same number of rows.", exception.getMessage());

			// With empty matrices.
			final List<List<ZqElement>> emptyMatrix = Collections.emptyList();
			final IllegalArgumentException exceptionSecondEmpty = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentProof.computeDVector(firstMatrix, emptyMatrix));
			assertEquals("The two matrices must have the same number of rows.", exceptionSecondEmpty.getMessage());

			final IllegalArgumentException exceptionFirstEmpty = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentProof.computeDVector(emptyMatrix, secondMatrix));
			assertEquals("The two matrices must have the same number of rows.", exceptionFirstEmpty.getMessage());
		}

		@Test
		@DisplayName("with first matrix having columns of different size throws IllegalArgumentException")
		void computeDVectorFirstMatrixDifferentColumnSize() {
			// Add an additional line to first matrix with less elements in the column.
			final List<ZqElement> lineWithSmallerColumn = generateRandomZqElementList(0, zqGroup);
			firstMatrix.add(lineWithSmallerColumn);

			// Also add additional line to second matrix to have same number of lines.
			final List<ZqElement> additionalLine = generateRandomZqElementList(n, zqGroup);
			secondMatrix.add(additionalLine);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentProof.computeDVector(firstMatrix, secondMatrix));
			assertEquals("All rows of the matrix must have the same number of columns.", exception.getMessage());
		}

		@Test
		@DisplayName("with second matrix having columns of different size throws IllegalArgumentException")
		void computeDVectorSecondMatrixDifferentColumnSize() {
			// Add an additional line to second matrix with less elements in the column.
			final List<ZqElement> lineWithSmallerColumn = generateRandomZqElementList(0, zqGroup);
			secondMatrix.add(lineWithSmallerColumn);

			// Also add additional line to first matrix to have same number of lines.
			final List<ZqElement> additionalLine = generateRandomZqElementList(n, zqGroup);
			firstMatrix.add(additionalLine);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentProof.computeDVector(firstMatrix, secondMatrix));
			assertEquals("All rows of the matrix must have the same number of columns.", exception.getMessage());
		}

		@Test
		@DisplayName("with matrices with different number of columns throws IllegalArgumentException")
		void computeDVectorDifferentSizeColumns() {
			final List<List<ZqElement>> otherFirstMatrix = generateRandomZqElementMatrix(m, n, zqGroup);
			final List<List<ZqElement>> otherSecondMatrix = generateRandomZqElementMatrix(m, n + 1, zqGroup);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentProof.computeDVector(otherFirstMatrix, otherSecondMatrix));
			assertEquals("The two matrices must have the same number of columns.", exception.getMessage());
		}

		@Test
		@DisplayName("with first matrix having elements of different groups throws IllegalArgumentException")
		void computeDVectorFirstMatrixDifferentGroup() {
			// Get a different ZqGroup.
			final ZqGroup otherZqGroup = getDifferentZqGroup();

			// Add an additional line to first matrix with elements from a different group.
			final List<ZqElement> differentGroupElements = generateRandomZqElementList(m + 1, otherZqGroup);
			firstMatrix.add(differentGroupElements);

			// Also add additional line to second matrix but from same group.
			final List<ZqElement> sameGroupElements = generateRandomZqElementList(m + 1, zqGroup);
			secondMatrix.add(sameGroupElements);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentProof.computeDVector(firstMatrix, secondMatrix));
			assertEquals("All elements of the matrix must be in the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("with second matrix having elements of different groups throws IllegalArgumentException")
		void computeDVectorSecondMatrixDifferentGroup() {
			// Get a different ZqGroup.
			final ZqGroup otherZqGroup = getDifferentZqGroup();

			// Add an additional line to second matrix with elements from a different group.
			final List<ZqElement> differentGroupElements = generateRandomZqElementList(m + 1, otherZqGroup);
			secondMatrix.add(differentGroupElements);

			// Also add additional line to fist matrix but from same group.
			final List<ZqElement> sameGroupElements = generateRandomZqElementList(m + 1, zqGroup);
			firstMatrix.add(sameGroupElements);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentProof.computeDVector(firstMatrix, secondMatrix));
			assertEquals("All elements of the matrix must be in the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("with second matrix having elements of different group than the first matrix throws IllegalArgumentException")
		void computeDVectorMatricesDifferentGroup() {
			// Get a second matrix in a different ZqGroup.
			final ZqGroup differentZqGroup = getDifferentZqGroup();
			final List<List<ZqElement>> differentGroupSecondMatrix = generateRandomZqElementMatrix(n, m + cim1, differentZqGroup);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentProof.computeDVector(firstMatrix, differentGroupSecondMatrix));
			assertEquals("The elements of both matrices must be in the same group.", exception.getMessage());
		}

		@RepeatedTest(100)
		@DisplayName("with random values gives expected d vector length")
		void computeDVectorTest() {
			assertEquals(2 * m + 1, zeroArgumentProof.computeDVector(firstMatrix, secondMatrix).size());
		}

		@Test
		@DisplayName("with empty matrices gives empty result vector")
		void computeDVectorEmptyMatrices() {
			final List<ZqElement> emptyD = Collections.emptyList();
			final List<List<ZqElement>> firstEmptyMatrix = Collections.emptyList();
			final List<List<ZqElement>> secondEmptyMatrix = Collections.emptyList();

			assertEquals(emptyD, zeroArgumentProof.computeDVector(firstEmptyMatrix, secondEmptyMatrix));
		}

		@Test
		@DisplayName("with matrices with empty columns gives empty result vector")
		void computeDVectorEmptyColumns() {
			final List<ZqElement> emptyD = Collections.emptyList();
			final List<List<ZqElement>> firstEmptyMatrix = Collections.singletonList(Collections.emptyList());
			final List<List<ZqElement>> secondEmptyMatrix = Collections.singletonList(Collections.emptyList());

			assertEquals(emptyD, zeroArgumentProof.computeDVector(firstEmptyMatrix, secondEmptyMatrix));
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
			zeroArgumentProof = new ZeroArgumentProof(y);

			// Expected d vector.
			final List<ZqElement> expected = Arrays
					.asList(ZqElement.create(FOUR, group), ZqElement.create(SEVEN, group), ZqElement.create(ZERO, group));

			assertEquals(expected, zeroArgumentProof.computeDVector(firstMatrix, secondMatrix));
		}
	}

	@Nested
	@DisplayName("starMap")
	class StarMapTest {

		private int n;

		@BeforeEach
		void setUp() {
			n = secureRandom.nextInt(10) + 1;
		}

		@Test
		@DisplayName("constructed with value y from different group throws IllegalArgumentException")
		void starMapYDifferentGroup() {
			final List<ZqElement> firstVector = generateRandomZqElementList(n, zqGroup);
			final List<ZqElement> secondVector = generateRandomZqElementList(n, zqGroup);

			// Get another y from a different group.
			final ZqGroup differentZqGroup = getDifferentZqGroup();
			final ZqElement differentGroupY = ZqElement.create(randomService.genRandomInteger(differentZqGroup.getQ()), differentZqGroup);

			// Construct with different y.
			zeroArgumentProof = new ZeroArgumentProof(differentGroupY);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentProof.starMap(firstVector, secondVector));
			assertEquals("The value y must be in the same group as the vectors elements", exception.getMessage());
		}

		@Test
		@DisplayName("with any null parameter throws NullPointerException")
		void starMapNullParams() {
			final List<ZqElement> firstVector = generateRandomZqElementList(n, zqGroup);
			final List<ZqElement> secondVector = generateRandomZqElementList(n, zqGroup);
			final List<ZqElement> emptyVector = Collections.emptyList();

			assertAll(
					() -> assertThrows(NullPointerException.class, () -> zeroArgumentProof.starMap(null, secondVector)),
					() -> assertThrows(NullPointerException.class, () -> zeroArgumentProof.starMap(null, emptyVector)),
					() -> assertThrows(NullPointerException.class, () -> zeroArgumentProof.starMap(firstVector, null)),
					() -> assertThrows(NullPointerException.class, () -> zeroArgumentProof.starMap(emptyVector, null))
			);
		}

		@Test
		@DisplayName("with vector having a null element throws IllegalArgumentException")
		void starMapNullElements() {
			final List<ZqElement> firstVector = generateRandomZqElementList(n, zqGroup);
			final List<ZqElement> secondVector = generateRandomZqElementList(n, zqGroup);

			final List<ZqElement> nullElemFirstVector = generateRandomZqElementList(n, zqGroup);
			nullElemFirstVector.set(0, null);
			final List<ZqElement> nullElemSecondVector = generateRandomZqElementList(n, zqGroup);
			nullElemSecondVector.set(0, null);

			final IllegalArgumentException exceptionFirst = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentProof.starMap(nullElemFirstVector, secondVector));
			assertEquals("The elements of the first vector must not be null.", exceptionFirst.getMessage());

			final IllegalArgumentException exceptionSecond = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentProof.starMap(firstVector, nullElemSecondVector));
			assertEquals("The elements of the second vector must not be null.", exceptionSecond.getMessage());

		}

		@Test
		@DisplayName("with vectors of different size throws IllegalArgumentException")
		void starMapVectorsDifferentSize() {
			final List<ZqElement> firstVector = generateRandomZqElementList(n, zqGroup);
			final List<ZqElement> secondVector = generateRandomZqElementList(n + 1, zqGroup);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentProof.starMap(firstVector, secondVector));
			assertEquals("The provided vectors must have the same size.", exception.getMessage());

			// With empty vectors.
			final List<ZqElement> emptyVector = Collections.emptyList();
			final IllegalArgumentException exceptionSecondEmpty = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentProof.starMap(firstVector, emptyVector));
			assertEquals("The provided vectors must have the same size.", exceptionSecondEmpty.getMessage());

			final IllegalArgumentException exceptionFirstEmpty = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentProof.starMap(emptyVector, secondVector));
			assertEquals("The provided vectors must have the same size.", exceptionFirstEmpty.getMessage());
		}

		@Test
		@DisplayName("with first vector having different group elements throws IllegalArgumentException")
		void starMapFirstVectorDifferentGroup() {
			final List<ZqElement> firstVector = generateRandomZqElementList(n, zqGroup);
			final List<ZqElement> secondVector = generateRandomZqElementList(n + 1, zqGroup);

			// Add an element from a different group to first vector.
			final ZqGroup differentZqGroup = getDifferentZqGroup();
			firstVector.add(ZqElement.create(randomService.genRandomInteger(differentZqGroup.getQ()), differentZqGroup));

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentProof.starMap(firstVector, secondVector));
			assertEquals("All elements must belong to the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("with second vector having different group elements throws IllegalArgumentException")
		void starMapSecondVectorDifferentGroup() {
			final List<ZqElement> firstVector = generateRandomZqElementList(n + 1, zqGroup);
			final List<ZqElement> secondVector = generateRandomZqElementList(n, zqGroup);

			// Add an element from a different group to second vector.
			final ZqGroup differentZqGroup = getDifferentZqGroup();
			secondVector.add(ZqElement.create(randomService.genRandomInteger(differentZqGroup.getQ()), differentZqGroup));

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentProof.starMap(firstVector, secondVector));
			assertEquals("All elements must belong to the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("with second vector elements of different group than the first vector throws IllegalArgumentException")
		void starMapVectorsDifferentGroup() {
			final List<ZqElement> firstVector = generateRandomZqElementList(n, zqGroup);

			// Second vector from different group.
			final ZqGroup differentZqGroup = getDifferentZqGroup();
			final List<ZqElement> secondVector = generateRandomZqElementList(n, differentZqGroup);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentProof.starMap(firstVector, secondVector));
			assertEquals("The elements of both vectors must be in the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("with empty vectors returns identity")
		void starMapEmptyVectors() {
			final List<ZqElement> firstVector = Collections.emptyList();
			final List<ZqElement> secondVector = Collections.emptyList();

			assertEquals(zqGroup.getIdentity(), zeroArgumentProof.starMap(firstVector, secondVector));
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
			zeroArgumentProof = new ZeroArgumentProof(y);

			// Expected starMap result.
			final ZqElement expected = ZqElement.create(ONE, group);

			assertEquals(expected, zeroArgumentProof.starMap(firstVector, secondVector));
		}
	}

	// ===============================================================================================================================================
	// Utility methods
	// ===============================================================================================================================================

	/**
	 * Generate a random vector of {@link ZqElement} in the specified {@code group}.
	 *
	 * @param numElements the number of elements to generate.
	 * @return a vector of {@code numElements} random {@link ZqElement}.
	 */
	private List<ZqElement> generateRandomZqElementList(final int numElements, final ZqGroup group) {
		return generateElementList(numElements, () -> ZqElement.create(randomService.genRandomInteger(group.getQ()), group));
	}

	/**
	 * Generate a random matrix of {@link ZqElement} in the specified {@code group}.
	 *
	 * @param m the matrix' number of lines.
	 * @param n the matrix' number of columns.
	 * @return a m &times; n matrix of random {@link ZqElement}.
	 */
	private List<List<ZqElement>> generateRandomZqElementMatrix(final int m, final int n, final ZqGroup group) {
		return generateElementMatrix(m, n, () -> ZqElement.create(randomService.genRandomInteger(group.getQ()), group));
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
}
