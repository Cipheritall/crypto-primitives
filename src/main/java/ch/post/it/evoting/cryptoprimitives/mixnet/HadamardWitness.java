/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import ch.post.it.evoting.cryptoprimitives.SameGroupMatrix;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

class HadamardWitness {

	private final SameGroupMatrix<ZqElement, ZqGroup> matrixA;
	private final SameGroupVector<ZqElement, ZqGroup> vectorB;
	private final SameGroupVector<ZqElement, ZqGroup> exponentsR;
	private final ZqElement exponentS;

	/**
	 * Constructs a {@code HadamardWitness} object.
	 * <p>
	 * The inputs must comply with the following:
	 * <ul>
	 *     <li>be non null</li>
	 *     <li>belong to the same {@link ZqGroup}</li>
	 *     <li>the number of rows of the matrix and the vector size must be equal</li>
	 *     <li>the number of columns of the matrix and the size of the exponents vector must be equal</li>
	 * </ul>
	 *
	 *
	 * @param matrix	 A, a matrix of {@code ZqElements} of size <i>n</i> &times; <i>m</i>
	 * @param vector	 b, a vector of {@code ZqElements} of size <i>n</i>
	 * @param exponents	 r, a vector of {@code ZqElements} of size <i>m</i>
	 * @param randomness s, a {@code ZqElement}
	 */
	HadamardWitness(final SameGroupMatrix<ZqElement, ZqGroup> matrix, final SameGroupVector<ZqElement, ZqGroup> vector,
			final SameGroupVector<ZqElement, ZqGroup> exponents, final ZqElement randomness) {
		checkNotNull(matrix);
		checkNotNull(vector);
		checkNotNull(exponents);
		checkNotNull(randomness);

		this.matrixA = matrix;
		this.vectorB = vector;
		this.exponentsR = exponents;
		this.exponentS = randomness;

		// Dimension checks
		checkArgument(matrixA.numRows() == vectorB.size(),
				"The matrix A must have the same number of rows as the vector b has elements.");
		checkArgument(matrixA.numColumns() == exponentsR.size(),
				"The matrix A must have the same number of columns as the exponents r have elements.");

		// Group checks
		checkArgument(matrixA.getGroup().equals(vectorB.getGroup()),
				"The matrix A and the vector b must have the same group.");
		checkArgument(matrixA.getGroup().equals(exponentsR.getGroup()),
				"The matrix A and the exponents r must have the same group.");
		checkArgument(exponentsR.getGroup().equals(exponentS.getGroup()),
				"The exponents r and the exponent s must have the same group.");
	}

	SameGroupMatrix<ZqElement, ZqGroup> getMatrixA() {
		return matrixA;
	}

	SameGroupVector<ZqElement, ZqGroup> getVectorB() {
		return vectorB;
	}

	SameGroupVector<ZqElement, ZqGroup> getExponentsR() {
		return exponentsR;
	}

	ZqElement getExponentS() {
		return exponentS;
	}
}
