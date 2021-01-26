/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.List;
import java.util.Objects;

import ch.post.it.evoting.cryptoprimitives.SameGroupMatrix;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

/**
 * Represents the witness for a zero argument, consisting of two matrices and two vectors of exponents.
 */
class ZeroWitness {

	private final SameGroupMatrix<ZqElement, ZqGroup> matrixA;
	private final SameGroupMatrix<ZqElement, ZqGroup> matrixB;
	private final SameGroupVector<ZqElement, ZqGroup> exponentsR;
	private final SameGroupVector<ZqElement, ZqGroup> exponentsS;

	/**
	 * Instantiate a zero witness. The matrices and exponents must comply with the following:
	 *
	 * <ul>
	 *     <li>be non null</li>
	 *     <li>the matrices must have the same number of rows and columns</li>
	 *     <li>the exponents vector must have the same size</li>
	 *     <li>the size of exponents vector must be the number of columns of the matrices</li>
	 * </ul>
	 *
	 * @param matrixA    A, a matrix of {@link ZqElement}s.
	 * @param matrixB    B, a matrix of {@link ZqElement}s.
	 * @param exponentsR r, a vector of {@link ZqElement}s.
	 * @param exponentsS s, a vector of {@link ZqElement}s.
	 */
	ZeroWitness(final List<List<ZqElement>> matrixA, final List<List<ZqElement>> matrixB, final List<ZqElement> exponentsR,
			final List<ZqElement> exponentsS) {

		// Null checking.
		checkNotNull(matrixA);
		checkNotNull(matrixB);
		checkNotNull(exponentsR);
		checkNotNull(exponentsS);

		// Immutable copies.
		this.matrixA = SameGroupMatrix.fromRows(matrixA);
		this.matrixB = SameGroupMatrix.fromRows(matrixB);
		this.exponentsR = new SameGroupVector<>(exponentsR);
		this.exponentsS = new SameGroupVector<>(exponentsS);

		// Dimensions checking.
		checkArgument(this.matrixA.rowSize() == this.matrixB.rowSize(), "The two matrices must have the same number of rows.");
		checkArgument(this.matrixA.columnSize() == this.matrixB.columnSize(), "The two matrices must have the same number of columns.");
		checkArgument(this.exponentsR.size() == this.exponentsS.size(), "The exponents vector must have the same size.");
		checkArgument(this.exponentsR.size() == this.matrixA.columnSize(),
				"The exponents vectors size must be the number of columns of the matrices.");

		// Group checking.
		if (!this.matrixA.isEmpty()) {
			final ZqGroup group = this.matrixA.getGroup();
			checkArgument(this.matrixB.getGroup().equals(group), "The matrices are not from the same group.");
			checkArgument(this.exponentsR.getGroup().equals(this.exponentsS.getGroup()), "The exponents are not from the same group.");
			checkArgument(this.exponentsR.getGroup().equals(group), "The matrices and exponents are not from the same group.");
		}
	}

	SameGroupMatrix<ZqElement, ZqGroup> getMatrixA() {
		return matrixA;
	}

	SameGroupMatrix<ZqElement, ZqGroup> getMatrixB() {
		return matrixB;
	}

	SameGroupVector<ZqElement, ZqGroup> getExponentsR() {
		return exponentsR;
	}

	SameGroupVector<ZqElement, ZqGroup> getExponentsS() {
		return exponentsS;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		ZeroWitness that = (ZeroWitness) o;
		return matrixA.equals(that.matrixA) && matrixB.equals(that.matrixB) && exponentsR.equals(that.exponentsR) && exponentsS
				.equals(that.exponentsS);
	}

	@Override
	public int hashCode() {
		return Objects.hash(matrixA, matrixB, exponentsR, exponentsS);
	}
}
