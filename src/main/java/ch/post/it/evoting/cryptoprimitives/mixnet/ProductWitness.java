/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Objects;

import ch.post.it.evoting.cryptoprimitives.SameGroupMatrix;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

/**
 * Represents a witness for a product argument.
 */
class ProductWitness {

	private final SameGroupMatrix<ZqElement, ZqGroup> matrix;
	private final SameGroupVector<ZqElement, ZqGroup> exponents;

	/**
	 * Instantiates a {@link ProductWitness} with the given matrix and exponents.
	 *
	 * <p>The matrix and the exponents must comply with the following:
	 * <ul>
	 *     <li>be non null</li>
	 *     <li>belong to the same {@link ZqGroup}</li>
	 *     <li>the number of columns in the matrix must be equal to the number of exponents</li>
	 * </ul>
	 *
	 * @param matrix    A, a {@link SameGroupMatrix} of {@code ZqElements}
	 * @param exponents <b><i>r</i></b>, a {@link SameGroupVector} of {@code ZqElements}
	 */
	ProductWitness(final SameGroupMatrix<ZqElement, ZqGroup> matrix, final SameGroupVector<ZqElement, ZqGroup> exponents) {
		checkNotNull(matrix);
		checkNotNull(exponents);
		checkArgument(matrix.numColumns() == exponents.size(),
				"The number of columns in the matrix must be equal to the number of exponents.");
		checkArgument(matrix.getGroup().equals(exponents.getGroup()),
				"The matrix and the exponents must belong to the same group.");

		this.matrix = matrix;
		this.exponents = exponents;
	}

	SameGroupMatrix<ZqElement, ZqGroup> getMatrix() {
		return matrix;
	}

	SameGroupVector<ZqElement, ZqGroup> getExponents() {
		return exponents;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		ProductWitness that = (ProductWitness) o;
		return matrix.equals(that.matrix) && exponents.equals(that.exponents);
	}

	@Override
	public int hashCode() {
		return Objects.hash(matrix, exponents);
	}
}
