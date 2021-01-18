/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives;

import static ch.post.it.evoting.cryptoprimitives.test.tools.generator.HasGroupElementGenerator.generateElementList;
import static ch.post.it.evoting.cryptoprimitives.test.tools.generator.HasGroupElementGenerator.generateElementMatrix;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.math.GroupElement;
import ch.post.it.evoting.cryptoprimitives.test.tools.TestHasGroupElement;
import ch.post.it.evoting.cryptoprimitives.test.tools.math.TestGroup;

class SameGroupMatrixTest {

	private static int BOUND_MATRIX_SIZE = 10;
	private static TestGroup group = new TestGroup();

	private final SecureRandom secureRandom = new SecureRandom();

	private int numRows;
	private int numColumns;
	private List<List<TestHasGroupElement>> matrixElements;

	@BeforeAll
	static void setup() {
		group = new TestGroup();
	}

	@BeforeEach
	void setUp() {
		numRows = secureRandom.nextInt(10) + 1;
		numColumns = secureRandom.nextInt(10) + 1;
		matrixElements = generateElementMatrix(numRows + 1, numColumns, () -> new TestHasGroupElement(group));
	}

	@Test
	void createSameGroupMatrixWithNullValues() {
		assertThrows(NullPointerException.class, () -> new SameGroupMatrix<>(null));
	}

	@Test
	void createSameGroupMatrixWithNullRows() {
		final List<List<TestHasGroupElement>> nullRowMatrix = generateElementMatrix(numRows, numColumns, () -> new TestHasGroupElement(group));
		int nullIndex = secureRandom.nextInt(numRows);
		nullRowMatrix.set(nullIndex, null);
		final IllegalArgumentException exceptionFirst = assertThrows(IllegalArgumentException.class, () -> new SameGroupMatrix<>(nullRowMatrix));
		assertEquals("A matrix cannot contain a null row.", exceptionFirst.getMessage());
	}

	@Test
	void createSameGroupMatrixWithNullElement() {
		final List<List<TestHasGroupElement>> nullElemMatrix = generateElementMatrix(numRows, numColumns, () -> new TestHasGroupElement(group));
		int nullRowIndex = secureRandom.nextInt(numRows);
		int nullColumnIndex = secureRandom.nextInt(numColumns);
		nullElemMatrix.get(nullRowIndex).set(nullColumnIndex, null);
		final IllegalArgumentException exceptionFirst = assertThrows(IllegalArgumentException.class, () -> new SameGroupMatrix<>(nullElemMatrix));
		assertEquals("A matrix cannot contain a null element.", exceptionFirst.getMessage());
	}

	@Test
	void createSameGroupMatrixWithDifferentColumnSize() {
		// Add an additional line to the matrix with less elements in the column.
		int numColumns = secureRandom.nextInt(this.numColumns);
		final List<TestHasGroupElement> lineWithSmallerColumn = generateElementList(numColumns, () -> new TestHasGroupElement(group));
		matrixElements.add(lineWithSmallerColumn);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> new SameGroupMatrix<>(matrixElements));
		assertEquals("All rows of the matrix must have the same number of columns.", exception.getMessage());
	}

	@Test
	void createSameGroupMatrixWithDifferentGroup() {
		final TestGroup otherGroup = new TestGroup();

		// Add an additional line to first matrix with elements from a different group.
		final List<TestHasGroupElement> differentGroupElements = generateElementList(numColumns, () -> new TestHasGroupElement(otherGroup));
		matrixElements.add(differentGroupElements);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> new SameGroupMatrix<>(matrixElements));
		assertEquals("All elements of the matrix must be in the same group.", exception.getMessage());
	}

	@Test
	void createSameGroupMatrixWithNoRows() {
		final List<List<TestHasGroupElement>> emptyMatrixElements = Collections.emptyList();
		SameGroupMatrix<TestHasGroupElement, TestGroup> emptyMatrix = new SameGroupMatrix<>(emptyMatrixElements);
		assertEquals(0, emptyMatrix.rowSize());
		assertEquals(0, emptyMatrix.columnSize());
	}

	@Test
	void createSameGroupMatrixWithNoColumns() {
		final List<List<TestHasGroupElement>> emptyMatrixElements = generateElementMatrix(numRows, 0, () -> new TestHasGroupElement(group));
		SameGroupMatrix<TestHasGroupElement, TestGroup> emptyMatrix = new SameGroupMatrix<>(emptyMatrixElements);
		assertEquals(numRows, emptyMatrix.rowSize());
		assertEquals(0, emptyMatrix.columnSize());
	}

	@RepeatedTest(10)
	void sizesAreCorrectForRandomMatrix() {
		int numRows = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		int numColumns = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		TestGroup group = new TestGroup();
		List<List<TestHasGroupElement>> matrixElements = generateElementMatrix(numRows, numColumns, () -> new TestHasGroupElement(group));
		SameGroupMatrix<TestHasGroupElement, TestGroup> matrix = new SameGroupMatrix<>(matrixElements);
		assertEquals(numRows, matrix.rowSize());
		assertEquals(numColumns, matrix.columnSize());
	}

	@Test
	void isEmptyReturnTrueForNoRows() {
		List<List<TestHasGroupElement>> emptyMatrixElements = Collections.emptyList();
		SameGroupMatrix<TestHasGroupElement, TestGroup> emptyMatrix = new SameGroupMatrix<>(emptyMatrixElements);
		assertTrue(emptyMatrix.isEmpty());
	}

	@Test
	void isEmptyReturnTrueForNoColumns() {
		List<List<TestHasGroupElement>> emptyMatrixElements = Collections.singletonList(Collections.emptyList());
		SameGroupMatrix<TestHasGroupElement, TestGroup> emptyMatrix = new SameGroupMatrix<>(emptyMatrixElements);
		assertTrue(emptyMatrix.isEmpty());
	}

	@Test
	void getThrowsForIndexOutOfBounds() {
		int numRows = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		int numColumns = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		TestGroup group = new TestGroup();
		List<List<TestHasGroupElement>> matrixElements = generateElementMatrix(numRows, numColumns, () -> new TestHasGroupElement(group));
		SameGroupMatrix<TestHasGroupElement, TestGroup> matrix = new SameGroupMatrix<>(matrixElements);
		assertThrows(IllegalArgumentException.class, () -> matrix.get(-1, 0));
		assertThrows(IllegalArgumentException.class, () -> matrix.get(numRows, 0));
		assertThrows(IllegalArgumentException.class, () -> matrix.get(0, -1));
		assertThrows(IllegalArgumentException.class, () -> matrix.get(0, numColumns));
	}

	@RepeatedTest(10)
	void getReturnsExpectedElement() {
		int numRows = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		int numColumns = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		TestGroup group = new TestGroup();
		SameGroupMatrix<TestValuedElement, TestGroup> matrix = generateIncrementingMatrix(numRows, numColumns, group);
		int row = secureRandom.nextInt(numRows);
		int column = secureRandom.nextInt(numColumns);
		assertEquals(numColumns * row + column, matrix.get(row, column).getValue().intValueExact());
	}

	@RepeatedTest(10)
	void getRowReturnsExpectedRow() {
		int numRows = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		int numColumns = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		TestGroup group = new TestGroup();
		SameGroupMatrix<TestValuedElement, TestGroup> matrix = generateIncrementingMatrix(numRows, numColumns, group);
		int row = secureRandom.nextInt(numRows);
		List<TestValuedElement> expected = generateIncrementingRow(row * numColumns, numColumns, group);
		assertEquals(expected, matrix.getRow(row));
	}

	@RepeatedTest(10)
	void getColumnReturnsExpectedColumn() {
		int numRows = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		int numColumns = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		TestGroup group = new TestGroup();
		SameGroupMatrix<TestValuedElement, TestGroup> matrix = generateIncrementingMatrix(numRows, numColumns, group);
		int column = secureRandom.nextInt(numColumns);
		List<TestValuedElement> expected = IntStream.range(0, numRows)
				.map(row -> row * numColumns + column)
				.mapToObj(value -> new TestValuedElement(BigInteger.valueOf(value), group))
				.collect(Collectors.toList());
		assertEquals(expected, matrix.getColumn(column));
	}

	private static class TestValuedElement extends GroupElement<TestGroup> {
		protected TestValuedElement(BigInteger value, TestGroup group) {
			super(value, group);
		}
	}

	//Generate a matrix with incrementing count.
	private SameGroupMatrix<TestValuedElement, TestGroup> generateIncrementingMatrix(int numRows, int numColumns, TestGroup group) {
		List<List<TestValuedElement>> matrixElements =
				IntStream.range(0, numRows)
						.mapToObj(row -> generateIncrementingRow(numColumns * row, numColumns, group))
						.collect(Collectors.toList());
		return new SameGroupMatrix<>(matrixElements);
	}

	//Generate a row with incrementing number starting at start.
	private List<TestValuedElement> generateIncrementingRow(int start, int numColumns, TestGroup group) {
		return IntStream.range(0, numColumns)
				.map(column -> start + column)
				.mapToObj(BigInteger::valueOf)
				.map(value -> new TestValuedElement(value, group))
				.collect(Collectors.toList());
	}
}
