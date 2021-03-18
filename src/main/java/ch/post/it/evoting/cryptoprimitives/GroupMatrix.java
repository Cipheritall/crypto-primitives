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
package ch.post.it.evoting.cryptoprimitives;

import static ch.post.it.evoting.cryptoprimitives.GroupVector.toGroupVector;
import static ch.post.it.evoting.cryptoprimitives.Validations.allEqual;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

import java.util.List;
import java.util.Objects;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Streams;

import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableList;
import ch.post.it.evoting.cryptoprimitives.math.MathematicalGroup;

/**
 * Represents a matrix of {@link GroupVectorElement} elements belonging to the same {@link MathematicalGroup} and having the same size.
 *
 * <p>Instances of this class are immutable. </p>
 *
 * @param <E> the type of elements this list contains.
 * @param <G> the group type the elements of the list belong to.
 */
public class GroupMatrix<E extends GroupVectorElement<G> & Hashable, G extends MathematicalGroup<G>> implements HashableList {

	private static final String OUT_OF_BOUNDS_MESSAGE = "Trying to access index out of bound.";

	private final G group;
	private final ImmutableList<GroupVector<E, G>> rows;
	private final int numRows;
	private final int numColumns;
	private final int elementSize;

	private GroupMatrix(final ImmutableList<GroupVector<E, G>> rows) {
		// Null checking.
		checkNotNull(rows);
		checkArgument(rows.stream().allMatch(Objects::nonNull), "A matrix cannot contain a null row.");

		// Size checking.
		checkArgument(allEqual(rows.stream(), GroupVector::size), "All rows of the matrix must have the same number of columns.");
		checkArgument(allEqual(rows.stream().flatMap(GroupVector::stream), GroupVectorElement::size), "All matrix elements must have the same size.");

		// Group checking.
		if (!isEmpty(rows) && !rows.get(0).isEmpty()) {
			checkArgument(allEqual(rows.stream(), GroupVector::getGroup), "All elements of the matrix must be in the same group.");
		}

		this.rows = isEmpty(rows) ? ImmutableList.of() : rows;
		this.numRows = isEmpty(rows) ? 0 : rows.size();
		this.numColumns = isEmpty(rows) ? 0 : rows.get(0).size();
		this.group = isEmpty(rows) ? null : rows.get(0).get(0).getGroup();
		this.elementSize = isEmpty(rows) ? 0 : rows.get(0).get(0).size();
	}

	/**
	 * Creates a GroupMatrix from rows of elements.
	 *
	 * <p>If no rows are provided or if the rows are empty, the matrix is considered empty and has dimensions 0x0. </p>
	 *
	 * @param rows the rows of the matrix, which must respect the following:
	 *             <li>the list must be non-null</li>
	 *             <li>the list must not contain any nulls</li>
	 *             <li>all rows must have the same size</li>
	 *             <li>all elements must be from the same {@link MathematicalGroup} </li>
	 *             <li>all elements must be the same size</li>
	 */
	public static <L extends List<E>, E extends GroupVectorElement<G> & Hashable, G extends MathematicalGroup<G>>
	GroupMatrix<E, G> fromRows(final List<L> rows) {
		//Null checks
		checkNotNull(rows);
		checkArgument(rows.stream().allMatch(Objects::nonNull), "A matrix cannot contain a null row.");

		final ImmutableList<GroupVector<E, G>> rowVectors = rows.stream()
				.map(GroupVector::from)
				.collect(toImmutableList());

		return new GroupMatrix<>(rowVectors);
	}

	/**
	 * Creates a GroupMatrix from columns of elements.
	 *
	 * <p>If no columns are provided or if the columns are empty, the matrix is considered empty and has dimensions 0x0. </p>
	 *
	 * @param columns the columns of the matrix, which must respect the following:
	 *                <li>the list must be non-null</li>
	 *                <li>the list must not contain any nulls</li>
	 *                <li>all columns must have the same size</li>
	 *                <li>all elements must be from the same {@link MathematicalGroup} </li>
	 *                <li>all elements must be the same size</li>
	 */
	public static <L extends List<E>, E extends GroupVectorElement<G> & Hashable, G extends MathematicalGroup<G>>
	GroupMatrix<E, G> fromColumns(final List<L> columns) {
		return fromRows(columns).transpose();
	}

	private static <E extends GroupVectorElement<G> & Hashable, G extends MathematicalGroup<G>>
	GroupMatrix<E, G> fromColumnVector(final ImmutableList<GroupVector<E, G>> columns) {
		return new GroupMatrix<>(columns).transpose();
	}

	/**
	 * Transposes this matrix.
	 * <p>
	 * The transpose M<sup>t</sup> of matrix M is defined by M<sup>t</sup><sub>i,j</sub> = M<sub>j,i</sub>. If M is a m &times; n matrix, its
	 * transpose M<sup>t</sup> is a n &times; m matrix.
	 *
	 * @return the transpose of this matrix
	 */
	public GroupMatrix<E, G> transpose() {
		return new GroupMatrix<>(IntStream.range(0, numColumns).mapToObj(this::getColumn).collect(toImmutableList()));
	}

	public int numRows() {
		return this.numRows;
	}

	public int numColumns() {
		return this.numColumns;
	}

	/**
	 * @return true if either matrix dimension is 0.
	 */
	public boolean isEmpty() {
		return isEmpty(this.rows);
	}

	private boolean isEmpty(final ImmutableList<GroupVector<E, G>> matrix) {
		return matrix.isEmpty() || matrix.get(0).isEmpty();
	}

	/**
	 * Gets a unique element of the matrix.
	 *
	 * @param row    the index of the row, 0 indexed.
	 * @param column the index of the column, 0 indexed.
	 * @return the specified element of the matrix.
	 */
	public E get(final int row, final int column) {
		checkArgument(row >= 0, "The index of a row cannot be negative.");
		checkArgument(row < numRows, "The index of a row cannot be larger than the number of rows of the matrix.");
		checkArgument(column >= 0, "The index of a column cannot be negative.");
		checkArgument(column < numColumns, "The index of a column cannot be larger than the number of columns of the matrix.");
		return this.rows.get(row).get(column);
	}

	/**
	 * @return the ith row. i must be within bounds.
	 */
	public GroupVector<E, G> getRow(final int i) {
		checkArgument(i >= 0, OUT_OF_BOUNDS_MESSAGE);
		checkArgument(i < this.numRows, OUT_OF_BOUNDS_MESSAGE);
		return this.rows.get(i);
	}

	/**
	 * @return the jth row. j must be within bounds.
	 */
	public GroupVector<E, G> getColumn(final int j) {
		checkArgument(j >= 0, OUT_OF_BOUNDS_MESSAGE);
		checkArgument(j < this.numColumns, OUT_OF_BOUNDS_MESSAGE);
		return this.rows.stream().map(row -> row.get(j)).collect(toGroupVector());
	}

	/**
	 * @return A flat stream of the matrix elements, row after row.
	 */
	public Stream<E> stream() {
		return this.rowStream().flatMap(GroupVector::stream);
	}

	/**
	 * @return A stream over the matrix' rows.
	 */
	public Stream<GroupVector<E, G>> rowStream() {
		return this.rows.stream();
	}

	/**
	 * @return A stream over the matrix' columns.
	 */
	public Stream<GroupVector<E, G>> columnStream() {
		return IntStream.range(0, numColumns)
				.mapToObj(this::getColumn);
	}

	/**
	 * Appends a new column to the matrix. Returns a new GroupMatrix. The new column must:
	 * <ul>
	 *     <li>be non null</li>
	 *     <li>have {@code numRows} elements</li>
	 *     <li>have the same group as the matrix'</li>
	 * </ul>
	 *
	 * @param column The new column to append.
	 * @return A new GroupMatrix with the appended {@code column}.
	 */
	public GroupMatrix<E, G> appendColumn(final GroupVector<E, G> column) {
		checkNotNull(column);
		checkArgument(column.size() == numRows,
				String.format("The new column size does not match size of matrix' columns. Size: %d, numRows: %d", column.size(), numRows));
		checkArgument(column.getElementSize() == this.elementSize, "The elements' size does not match this matrix's elements' size.");
		if (!column.isEmpty()) {
			checkArgument(column.getGroup().equals(this.getGroup()), "The group of the new column must be equal to the matrix' group");
		}

		final ImmutableList<GroupVector<E, G>> newColumns = Streams.concat(this.columnStream(), Stream.of(column)).collect(toImmutableList());
		return GroupMatrix.fromColumnVector(newColumns);
	}

	/**
	 * Prepends a new column to the matrix. Returns a new GroupMatrix. The new column must:
	 * <ul>
	 *     <li>be non null</li>
	 *     <li>have {@code numRows} elements</li>
	 *     <li>have the same group as the matrix'</li>
	 * </ul>
	 *
	 * @param column The new column to prepend.
	 * @return A new GroupMatrix with the prepended {@code column}.
	 */
	public GroupMatrix<E, G> prependColumn(final GroupVector<E, G> column) {
		checkNotNull(column);
		checkArgument(column.size() == numRows,
				String.format("The new column size does not match size of matrix' columns. Size: %d, numRows: %d", column.size(), numRows));
		checkArgument(column.getElementSize() == this.elementSize, "The elements' size does not match this matrix's elements' size.");
		if (!column.isEmpty()) {
			checkArgument(column.getGroup().equals(this.getGroup()), "The group of the new column must be equal to the matrix' group");
		}

		final ImmutableList<GroupVector<E, G>> newColumns = Streams.concat(Stream.of(column), this.columnStream()).collect(toImmutableList());
		return GroupMatrix.fromColumnVector(newColumns);
	}

	public G getGroup() {
		return this.group;
	}

	/**
	 * @return the size of the elements. 0 if the matrix is empty.
	 */
	public Integer getElementSize() {
		return elementSize;
	}

	@Override
	public boolean equals(final Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		final GroupMatrix<?, ?> that = (GroupMatrix<?, ?>) o;
		return rows.equals(that.rows);
	}

	@Override
	public int hashCode() {
		return Objects.hash(rows);
	}

	@Override
	public String toString() {
		return "GroupMatrix{" + "rows=" + rows + '}';
	}

	@Override
	public ImmutableList<? extends Hashable> toHashableForm() {
		return this.rows;
	}
}
