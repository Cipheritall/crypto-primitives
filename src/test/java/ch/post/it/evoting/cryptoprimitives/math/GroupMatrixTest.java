/*
 *
 *  Copyright 2022 Post CH Ltd
 * 
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package ch.post.it.evoting.cryptoprimitives.math;

import static ch.post.it.evoting.cryptoprimitives.math.GroupVector.toGroupVector;
import static ch.post.it.evoting.cryptoprimitives.test.tools.generator.GroupVectorElementGenerator.generateElementList;
import static ch.post.it.evoting.cryptoprimitives.test.tools.generator.GroupVectorElementGenerator.generateElementMatrix;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.test.tools.TestGroupElement;
import ch.post.it.evoting.cryptoprimitives.test.tools.TestSizedElement;
import ch.post.it.evoting.cryptoprimitives.test.tools.math.TestGroup;

class GroupMatrixTest {

	private static final int BOUND_MATRIX_SIZE = 10;
	private static TestGroup group = new TestGroup();

	private final SecureRandom secureRandom = new SecureRandom();

	private int numRows;
	private int numColumns;
	private List<List<TestGroupElement>> matrixElements;

	@BeforeAll
	static void setup() {
		group = new TestGroup();
	}

	@BeforeEach
	void setUp() {
		numRows = secureRandom.nextInt(10) + 1;
		numColumns = secureRandom.nextInt(10) + 1;
		matrixElements = generateElementMatrix(numRows + 1, numColumns, () -> new TestGroupElement(group));
	}

	@Test
	void createGroupMatrixWithNullValues() {
		assertThrows(NullPointerException.class, () -> GroupMatrix.fromRows(null));
	}

	@Test
	void createGroupMatrixWithNullRows() {
		final List<List<TestGroupElement>> nullRowMatrix = generateElementMatrix(numRows, numColumns, () -> new TestGroupElement(group));
		int nullIndex = secureRandom.nextInt(numRows);
		nullRowMatrix.set(nullIndex, null);
		final IllegalArgumentException exceptionFirst = assertThrows(IllegalArgumentException.class, () -> GroupMatrix.fromRows(nullRowMatrix));
		assertEquals("A matrix cannot contain a null row.", exceptionFirst.getMessage());
	}

	@Test
	void createGroupMatrixWithNullElement() {
		final List<List<TestGroupElement>> nullElemMatrix = generateElementMatrix(numRows, numColumns, () -> new TestGroupElement(group));
		int nullRowIndex = secureRandom.nextInt(numRows);
		int nullColumnIndex = secureRandom.nextInt(numColumns);
		nullElemMatrix.get(nullRowIndex).set(nullColumnIndex, null);
		final IllegalArgumentException exceptionFirst = assertThrows(IllegalArgumentException.class, () -> GroupMatrix.fromRows(nullElemMatrix));
		assertEquals("Elements must not contain nulls", exceptionFirst.getMessage());
	}

	@Test
	void createGroupMatrixWithDifferentColumnSize() {
		// Add an additional line to the matrix with less elements in the column.
		int numColumns = secureRandom.nextInt(this.numColumns);
		final List<TestGroupElement> lineWithSmallerColumn = generateElementList(numColumns, () -> new TestGroupElement(group));
		matrixElements.add(lineWithSmallerColumn);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> GroupMatrix.fromRows(matrixElements));
		assertEquals("All rows of the matrix must have the same number of columns.", exception.getMessage());
	}

	@Test
	void createGroupMatrixWithDifferentGroup() {
		final TestGroup otherGroup = new TestGroup();

		// Add an additional line to first matrix with elements from a different group.
		final List<TestGroupElement> differentGroupElements = generateElementList(numColumns, () -> new TestGroupElement(otherGroup));
		matrixElements.add(differentGroupElements);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> GroupMatrix.fromRows(matrixElements));
		assertEquals("All elements of the matrix must be in the same group.", exception.getMessage());
	}


	@Test
	void createGroupMatrixWithDifferentSizes() {
		TestGroup group = new TestGroup();
		TestSizedElement first = new TestSizedElement(group, 1);
		TestSizedElement second = new TestSizedElement(group, 2);
		List<List<TestSizedElement>> elements = Collections.singletonList(Arrays.asList(first, second));
		assertThrows(IllegalArgumentException.class, () -> GroupMatrix.fromRows(elements));
	}

	@RepeatedTest(10)
	void sizesAreCorrectForRandomMatrix() {
		int numRows = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		int numColumns = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		TestGroup group = new TestGroup();
		List<List<TestGroupElement>> matrixElements = generateElementMatrix(numRows, numColumns, () -> new TestGroupElement(group));
		GroupMatrix<TestGroupElement, TestGroup> matrix = GroupMatrix.fromRows(matrixElements);
		assertEquals(numRows, matrix.numRows());
		assertEquals(numColumns, matrix.numColumns());
	}

	@Test
	void getThrowsForIndexOutOfBounds() {
		int numRows = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		int numColumns = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		TestGroup group = new TestGroup();
		List<List<TestGroupElement>> matrixElements = generateElementMatrix(numRows, numColumns, () -> new TestGroupElement(group));
		GroupMatrix<TestGroupElement, TestGroup> matrix = GroupMatrix.fromRows(matrixElements);
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
		GroupMatrix<TestValuedElement, TestGroup> matrix = generateIncrementingMatrix(numRows, numColumns, group);
		int row = secureRandom.nextInt(numRows);
		int column = secureRandom.nextInt(numColumns);
		assertEquals(numColumns * row + column, matrix.get(row, column).getValue().intValueExact());
	}

	@RepeatedTest(10)
	void getRowReturnsExpectedRow() {
		int numRows = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		int numColumns = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		TestGroup group = new TestGroup();
		GroupMatrix<TestValuedElement, TestGroup> matrix = generateIncrementingMatrix(numRows, numColumns, group);
		int row = secureRandom.nextInt(numRows);
		List<TestValuedElement> expected = generateIncrementingRow(row * numColumns, numColumns, group);
		assertEquals(GroupVector.from(expected), matrix.getRow(row));
	}

	@RepeatedTest(10)
	void getColumnReturnsExpectedColumn() {
		int numRows = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		int numColumns = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		TestGroup group = new TestGroup();
		GroupMatrix<TestValuedElement, TestGroup> matrix = generateIncrementingMatrix(numRows, numColumns, group);
		int column = secureRandom.nextInt(numColumns);
		GroupVector<TestValuedElement, TestGroup> expected = IntStream.range(0, numRows)
				.map(row -> row * numColumns + column)
				.mapToObj(value -> new TestValuedElement(BigInteger.valueOf(value), group))
				.collect(toGroupVector());
		assertEquals(expected, matrix.getColumn(column));
	}

	@RepeatedTest(10)
	void matrixFromColumnsIsMatrixFromRowsTransposed() {
		int n = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		int m = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		List<List<TestGroupElement>> rows = generateElementMatrix(n, m, () -> new TestGroupElement(group));
		GroupMatrix<TestGroupElement, TestGroup> expected = GroupMatrix.fromRows(rows);

		List<List<TestGroupElement>> columns =
				IntStream.range(0, m)
						.mapToObj(column ->
								rows.stream()
										.map(row -> row.get(column))
										.toList()
						).toList();
		GroupMatrix<TestGroupElement, TestGroup> actual = GroupMatrix.fromColumns(columns);

		assertEquals(expected, actual);
	}

	@Test
	void transposeCorrectlyTransposesMatrix() {
		final List<List<TestGroupElement>> matrixElements = generateElementMatrix(numRows, numColumns, () -> new TestGroupElement(group));
		final GroupMatrix<TestGroupElement, TestGroup> matrix = GroupMatrix.fromRows(matrixElements);
		final GroupMatrix<TestGroupElement, TestGroup> transposedMatrix = matrix.transpose();

		assertAll(
				() -> assertEquals(matrix.numColumns(), transposedMatrix.numRows()),
				() -> assertEquals(matrix.numRows(), transposedMatrix.numColumns()),
				() -> assertEquals(matrix.rowStream().collect(Collectors.toList()), transposedMatrix.columnStream().toList())
		);
	}

	@Test
	void transposeTwiceGivesOriginalMatrix() {
		final List<List<TestGroupElement>> matrixElements = generateElementMatrix(numRows, numColumns, () -> new TestGroupElement(group));
		final GroupMatrix<TestGroupElement, TestGroup> matrix = GroupMatrix.fromRows(matrixElements);
		assertEquals(matrix, matrix.transpose().transpose());
	}

	@Test
	void transposedMatrixContainsExpectedValues() {
		List<List<TestValuedElement>> matrixElements = new ArrayList<>();
		TestValuedElement zero = new TestValuedElement(BigInteger.ZERO, group);
		TestValuedElement one = new TestValuedElement(BigInteger.ONE, group);
		TestValuedElement ten = new TestValuedElement(BigInteger.TEN, group);
		matrixElements.add(Arrays.asList(zero, one, ten));
		matrixElements.add(Arrays.asList(one, ten, zero));

		final GroupMatrix<TestValuedElement, TestGroup> matrix = GroupMatrix.fromRows(matrixElements);
		final GroupMatrix<TestValuedElement, TestGroup> transposedMatrix = matrix.transpose();

		assertAll(
				() -> assertEquals(zero, transposedMatrix.get(0, 0)),
				() -> assertEquals(one, transposedMatrix.get(0, 1)),
				() -> assertEquals(one, transposedMatrix.get(1, 0)),
				() -> assertEquals(ten, transposedMatrix.get(1, 1)),
				() -> assertEquals(ten, transposedMatrix.get(2, 0)),
				() -> assertEquals(zero, transposedMatrix.get(2, 1))
		);
	}

	@RepeatedTest(10)
	void streamGivesElementsInCorrectOrder() {
		final int numRows = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		final int numColumns = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		final TestGroup group = new TestGroup();
		final List<List<TestGroupElement>> matrixElements = generateElementMatrix(numRows, numColumns, () -> new TestGroupElement(group));
		final GroupMatrix<TestGroupElement, TestGroup> matrix = GroupMatrix.fromRows(matrixElements);

		final int totalElements = numRows * numColumns;
		assertEquals(totalElements, matrix.flatStream().count());

		final List<TestGroupElement> flatMatrix = matrix.flatStream().toList();
		final int i = numRows - 1;
		final int j = numColumns - 1;
		// Index in new list is: i * numColumns + j
		assertEquals(matrix.get(0, 0), flatMatrix.get(0));
		assertEquals(matrix.get(0, j), flatMatrix.get(j));
		assertEquals(matrix.get(i, 0), flatMatrix.get(i * numColumns));
		assertEquals(matrix.get(i, j), flatMatrix.get(totalElements - 1));
	}

	@RepeatedTest(10)
	void rowStreamGivesRows() {
		final int numRows = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		final int numColumns = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		final TestGroup group = new TestGroup();
		final List<List<TestGroupElement>> matrixElements = generateElementMatrix(numRows, numColumns, () -> new TestGroupElement(group));
		final GroupMatrix<TestGroupElement, TestGroup> matrix = GroupMatrix.fromRows(matrixElements);

		assertEquals(numRows, matrix.rowStream().count());
		assertEquals(matrixElements.stream().map(GroupVector::from).collect(Collectors.toList()), matrix.rowStream().collect(Collectors.toList()));
	}

	@RepeatedTest(10)
	void columnStreamGivesColumns() {
		final int numRows = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		final int numColumns = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		final TestGroup group = new TestGroup();
		final List<List<TestGroupElement>> matrixElements = generateElementMatrix(numRows, numColumns, () -> new TestGroupElement(group));
		final GroupMatrix<TestGroupElement, TestGroup> matrix = GroupMatrix.fromRows(matrixElements);

		assertEquals(numColumns, matrix.columnStream().count());

		final List<List<TestGroupElement>> columnMatrixElements = IntStream.range(0, matrix.numColumns())
				.mapToObj(i -> matrixElements.stream().map(row -> row.get(i)).collect(Collectors.toList())).toList();
		assertEquals(columnMatrixElements.stream().map(GroupVector::from).collect(Collectors.toList()),
				matrix.columnStream().collect(Collectors.toList()));
	}

	@Test
	void appendColumnWithInvalidParamsThrows() {
		final int numRows = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		final int numColumns = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		final TestGroup group = new TestGroup();
		final List<List<TestGroupElement>> matrixElements = generateElementMatrix(numRows, numColumns, () -> new TestGroupElement(group));
		final GroupMatrix<TestGroupElement, TestGroup> matrix = GroupMatrix.fromRows(matrixElements);

		assertThrows(NullPointerException.class, () -> matrix.appendColumn(null));

		final GroupVector<TestGroupElement, TestGroup> emptyVector = GroupVector.of();
		final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> matrix.appendColumn(emptyVector));
		assertEquals(String.format("The new column size does not match size of matrix' columns. Size: %d, numRows: %d", 0, numRows),
				illegalArgumentException.getMessage());
	}

	@Test
	void appendColumnWithDifferentElementSizeThrows() {
		final int numRows = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		final int numColumns = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		final TestGroup group = new TestGroup();
		final List<List<TestSizedElement>> matrixElements =
				generateElementMatrix(numRows, numColumns, () -> new TestSizedElement(group, 1));
		final GroupMatrix<TestSizedElement, TestGroup> matrix = GroupMatrix.fromRows(matrixElements);

		List<TestSizedElement> elements = generateElementList(numRows, () -> new TestSizedElement(group, 2));
		final GroupVector<TestSizedElement, TestGroup> vector = GroupVector.from(elements);
		final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> matrix.appendColumn(vector));
		assertEquals("The elements' size does not match this matrix's elements' size.",
				illegalArgumentException.getMessage());
	}

	@Test
	void appendColumnOfDifferentGroupThrows() {
		final int numRows = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		final int numColumns = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		final TestGroup group = new TestGroup();
		final List<List<TestGroupElement>> matrixElements = generateElementMatrix(numRows, numColumns, () -> new TestGroupElement(group));
		final GroupMatrix<TestGroupElement, TestGroup> matrix = GroupMatrix.fromRows(matrixElements);

		final TestGroup differentTestGroup = new TestGroup();
		final GroupVector<TestGroupElement, TestGroup> newCol = GroupVector.from(
				generateElementList(numRows, () -> new TestGroupElement(differentTestGroup)));

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> matrix.appendColumn(newCol));
		assertEquals("The group of the new column must be equal to the matrix' group", exception.getMessage());
	}

	@RepeatedTest(10)
	void appendColumnCorrectlyAppends() {
		final int numRows = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		final int numColumns = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		final TestGroup group = new TestGroup();
		final List<List<TestGroupElement>> matrixElements = generateElementMatrix(numRows, numColumns, () -> new TestGroupElement(group));
		final GroupMatrix<TestGroupElement, TestGroup> matrix = GroupMatrix.fromRows(matrixElements);

		final GroupVector<TestGroupElement, TestGroup> newCol = GroupVector.from(
				generateElementList(numRows, () -> new TestGroupElement(group)));
		final GroupMatrix<TestGroupElement, TestGroup> augmentedMatrix = matrix.appendColumn(newCol);

		assertEquals(numColumns + 1, augmentedMatrix.numColumns());
		assertEquals(newCol, augmentedMatrix.getColumn(numColumns));
	}

	@Test
	void prependColumnWithInvalidParamsThrows() {
		final int numRows = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		final int numColumns = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		final TestGroup group = new TestGroup();
		final List<List<TestGroupElement>> matrixElements = generateElementMatrix(numRows, numColumns, () -> new TestGroupElement(group));
		final GroupMatrix<TestGroupElement, TestGroup> matrix = GroupMatrix.fromRows(matrixElements);

		assertThrows(NullPointerException.class, () -> matrix.prependColumn(null));

		final GroupVector<TestGroupElement, TestGroup> emptyVector = GroupVector.of();
		final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> matrix.prependColumn(emptyVector));
		assertEquals(String.format("The new column size does not match size of matrix' columns. Size: %d, numRows: %d", 0, numRows),
				illegalArgumentException.getMessage());
	}

	@Test
	void prependColumnWithDifferentElementSizeThrows() {
		final int numRows = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		final int numColumns = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		final TestGroup group = new TestGroup();
		final List<List<TestSizedElement>> matrixElements =
				generateElementMatrix(numRows, numColumns, () -> new TestSizedElement(group, 1));
		final GroupMatrix<TestSizedElement, TestGroup> matrix = GroupMatrix.fromRows(matrixElements);

		List<TestSizedElement> elements = generateElementList(numRows, () -> new TestSizedElement(group, 2));
		final GroupVector<TestSizedElement, TestGroup> vector = GroupVector.from(elements);
		final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> matrix.prependColumn(vector));
		assertEquals("The elements' size does not match this matrix's elements' size.",
				illegalArgumentException.getMessage());
	}

	@Test
	void prependColumnOfDifferentGroupThrows() {
		final int numRows = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		final int numColumns = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		final TestGroup group = new TestGroup();
		final List<List<TestGroupElement>> matrixElements = generateElementMatrix(numRows, numColumns, () -> new TestGroupElement(group));
		final GroupMatrix<TestGroupElement, TestGroup> matrix = GroupMatrix.fromRows(matrixElements);

		final TestGroup differentTestGroup = new TestGroup();
		final GroupVector<TestGroupElement, TestGroup> newCol = GroupVector.from(
				generateElementList(numRows, () -> new TestGroupElement(differentTestGroup)));

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> matrix.prependColumn(newCol));
		assertEquals("The group of the new column must be equal to the matrix' group", exception.getMessage());
	}

	@RepeatedTest(10)
	void prependColumnCorrectlyPrepends() {
		final int numRows = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		final int numColumns = secureRandom.nextInt(BOUND_MATRIX_SIZE) + 1;
		final TestGroup group = new TestGroup();
		final List<List<TestGroupElement>> matrixElements = generateElementMatrix(numRows, numColumns, () -> new TestGroupElement(group));
		final GroupMatrix<TestGroupElement, TestGroup> matrix = GroupMatrix.fromRows(matrixElements);

		final GroupVector<TestGroupElement, TestGroup> newCol = GroupVector.from(
				generateElementList(numRows, () -> new TestGroupElement(group)));
		final GroupMatrix<TestGroupElement, TestGroup> augmentedMatrix = matrix.prependColumn(newCol);

		assertEquals(numColumns + 1, augmentedMatrix.numColumns());
		assertEquals(newCol, augmentedMatrix.getColumn(0));
	}

	//***************************//
	// Utilities //
	//***************************//

	//Generate a matrix with incrementing count.
	private GroupMatrix<TestValuedElement, TestGroup> generateIncrementingMatrix(int numRows, int numColumns, TestGroup group) {
		List<List<TestValuedElement>> matrixElements =
				IntStream.range(0, numRows)
						.mapToObj(row -> generateIncrementingRow(numColumns * row, numColumns, group))
						.collect(Collectors.toList());
		return GroupMatrix.fromRows(matrixElements);
	}

	//Generate a row with incrementing number starting at start.
	private List<TestValuedElement> generateIncrementingRow(int start, int numColumns, TestGroup group) {
		return IntStream.range(0, numColumns)
				.map(column -> start + column)
				.mapToObj(BigInteger::valueOf)
				.map(value -> new TestValuedElement(value, group))
				.collect(Collectors.toList());
	}

	private static class TestValuedElement extends GroupElement<TestGroup> {
		protected TestValuedElement(BigInteger value, TestGroup group) {
			super(value, group);
		}
	}
}
