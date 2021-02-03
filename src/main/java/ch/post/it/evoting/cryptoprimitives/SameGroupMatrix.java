/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives;

import static ch.post.it.evoting.cryptoprimitives.Validations.allEqual;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Streams;

import ch.post.it.evoting.cryptoprimitives.math.MathematicalGroup;

/**
 * Matrix of {@link HasGroup} elements belonging to the same {@link MathematicalGroup}.
 *
 * <p>Instances of this class are immutable. </p>
 *
 * @param <E> the type of elements this list contains.
 * @param <G> the group type the elements of the list belong to.
 */
public class SameGroupMatrix<E extends HasGroup<G>, G extends MathematicalGroup<G>> implements HasGroup<G> {

	private final G group;
	private final ImmutableList<SameGroupVector<E, G>> rows;
	private final int rowSize;
	private final int columnSize;

	private SameGroupMatrix(final ImmutableList<SameGroupVector<E, G>> rows) {
		// Null checking.
		checkNotNull(rows);
		checkArgument(rows.stream().allMatch(Objects::nonNull), "A matrix cannot contain a null row.");

		// Size checking.
		checkArgument(allEqual(rows.stream(), SameGroupVector::size), "All rows of the matrix must have the same number of columns.");

		// Group checking.
		if (!isEmpty(rows) && !rows.get(0).isEmpty()) {
			checkArgument(allEqual(rows.stream(), SameGroupVector::getGroup), "All elements of the matrix must be in the same group.");
		}

		this.rows = isEmpty(rows) ? ImmutableList.of() : rows;
		this.rowSize = isEmpty(rows) ? 0 : rows.size();
		this.columnSize = isEmpty(rows) ? 0 : rows.get(0).size();
		this.group = isEmpty(rows) ? null : rows.get(0).get(0).getGroup();
	}

	/**
	 * Create a SameGroupMatrix from rows of elements.
	 *
	 * <p>If no rows are provided or if the rows are empty, the matrix is considered empty and has dimensions 0x0. </p>
	 *
	 * @param rows the rows of the matrix, which must respect the following:
	 *             <li>the list must be non-null</li>
	 *             <li>the list must not contain any nulls</li>
	 *             <li>all rows must have the same size</li>
	 *             <li>all elements must be from the same {@link MathematicalGroup} </li>
	 */
	public static <L extends List<E>, E extends HasGroup<G>, G extends MathematicalGroup<G>>
	SameGroupMatrix<E, G> fromRows(List<L> rows) {
		//Null checks
		checkNotNull(rows);
		checkArgument(rows.stream().allMatch(Objects::nonNull), "A matrix cannot contain a null row.");

		final ImmutableList<SameGroupVector<E, G>> rowVectors = rows.stream()
				.map(SameGroupVector::new)
				.collect(toImmutableList());

		return new SameGroupMatrix<>(rowVectors);
	}

	/**
	 * Create a SameGroupMatrix from columns of elements.
	 *
	 * <p>If no columns are provided or if the columns are empty, the matrix is considered empty and has dimensions 0x0. </p>
	 *
	 * @param columns the columns of the matrix, which must respect the following:
	 *                <li>the list must be non-null</li>
	 *                <li>the list must not contain any nulls</li>
	 *                <li>all columns must have the same size</li>
	 *                <li>all elements must be from the same {@link MathematicalGroup} </li>
	 */
	public static <L extends List<E>, E extends HasGroup<G>, G extends MathematicalGroup<G>>
	SameGroupMatrix<E, G> fromColumns(List<L> columns) {
		return fromRows(columns).transpose();
	}

	private static <E extends HasGroup<G>, G extends MathematicalGroup<G>>
	SameGroupMatrix<E, G> fromColumnVector(final ImmutableList<SameGroupVector<E, G>> columns) {
		return new SameGroupMatrix<>(columns).transpose();
	}

	private SameGroupMatrix<E, G> transpose() {
		return new SameGroupMatrix<>(IntStream.range(0, columnSize).mapToObj(this::getColumn).collect(toImmutableList()));
	}

	public int rowSize() {
		return this.rowSize;
	}

	public int columnSize() {
		return this.columnSize;
	}

	/**
	 * @return true if either matrix dimension is 0.
	 */
	public boolean isEmpty() {
		return isEmpty(this.rows);
	}

	private boolean isEmpty(ImmutableList<SameGroupVector<E, G>> matrix) {
		return matrix.isEmpty() || matrix.get(0).isEmpty();
	}

	/**
	 * Get a unique element of the matrix.
	 *
	 * @param row    the index of the row, 0 indexed.
	 * @param column the index of the column, 0 indexed.
	 * @return the specified element of the matrix.
	 */
	public E get(int row, int column) {
		checkArgument(row >= 0, "The index of a row cannot be negative.");
		checkArgument(row < rowSize, "The index of a row cannot be larger than the number of rows of the matrix.");
		checkArgument(column >= 0, "The index of a column cannot be negative.");
		checkArgument(column < columnSize, "The index of a columnd cannot be larger than the number of columns of the matrix.");
		return this.rows.get(row).get(column);
	}

	/**
	 * @return the ith row. i must be within bounds.
	 */
	public SameGroupVector<E, G> getRow(int i) {
		checkArgument(i >= 0);
		checkArgument(i < this.rowSize);
		return this.rows.get(i);
	}

	/**
	 * @return the jth row. j must be within bounds.
	 */
	public SameGroupVector<E, G> getColumn(int j) {
		checkArgument(j >= 0);
		checkArgument(j < this.columnSize);
		return this.rows.stream().map(row -> row.get(j)).collect(Collectors.collectingAndThen(Collectors.toList(), SameGroupVector::new));
	}

	/**
	 * @return A flat stream of the matrix elements, row after row.
	 */
	public Stream<E> stream() {
		return IntStream.range(0, this.rowSize())
				.mapToObj(this::getRow)
				.flatMap(SameGroupVector::stream);
	}

	/**
	 * @return A stream over the matrix' rows.
	 */
	public Stream<SameGroupVector<E, G>> rowStream() {
		return this.rows.stream();
	}

	/**
	 * @return A stream over the matrix' columns.
	 */
	public Stream<SameGroupVector<E, G>> columnStream() {
		return IntStream.range(0, columnSize)
				.mapToObj(this::getColumn);
	}

	/**
	 * Append a new column to the matrix. Returns a new SameGroupMatrix. The new column must:
	 * <ul>
	 *     <li>be non null</li>
	 *     <li>have {@code rowSize} elements</li>
	 *     <li>have the same group as the matrix'</li>
	 * </ul>
	 *
	 * @param column The new column to append.
	 * @return A new SameGroupMatrix with the appended {@code column}.
	 */
	public SameGroupMatrix<E, G> appendColumn(final SameGroupVector<E, G> column) {
		checkNotNull(column);
		checkArgument(column.size() == rowSize,
				String.format("The new column size does not match size of matrix' columns. Size: %d, rowSize: %d", column.size(), rowSize));
		if (!column.isEmpty()) {
			checkArgument(column.getGroup().equals(this.getGroup()), "The group of the new column must be equal to the matrix' group");
		}

		final ImmutableList<SameGroupVector<E, G>> newColumns = Streams.concat(this.columnStream(), Stream.of(column)).collect(toImmutableList());
		return SameGroupMatrix.fromColumnVector(newColumns);
	}

	/**
	 * Prepend a new column to the matrix. Returns a new SameGroupMatrix. The new column must:
	 * <ul>
	 *     <li>be non null</li>
	 *     <li>have {@code rowSize} elements</li>
	 *     <li>have the same group as the matrix'</li>
	 * </ul>
	 *
	 * @param column The new column to prepend.
	 * @return A new SameGroupMatrix with the prepended {@code column}.
	 */
	public SameGroupMatrix<E, G> prependColumn(final SameGroupVector<E, G> column) {
		checkNotNull(column);
		checkArgument(column.size() == rowSize,
				String.format("The new column size does not match size of matrix' columns. Size: %d, rowSize: %d", column.size(), rowSize));
		if (!column.isEmpty()) {
			checkArgument(column.getGroup().equals(this.getGroup()), "The group of the new column must be equal to the matrix' group");
		}

		final ImmutableList<SameGroupVector<E, G>> newColumns = Streams.concat(Stream.of(column), this.columnStream()).collect(toImmutableList());
		return SameGroupMatrix.fromColumnVector(newColumns);
	}

	@Override
	public G getGroup() {
		return this.group;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		SameGroupMatrix<?, ?> that = (SameGroupMatrix<?, ?>) o;
		return rows.equals(that.rows);
	}

	@Override
	public int hashCode() {
		return Objects.hash(rows);
	}

	@Override
	public String toString() {
		return "SameGroupMatrix{" + "rows=" + rows + '}';
	}
}
