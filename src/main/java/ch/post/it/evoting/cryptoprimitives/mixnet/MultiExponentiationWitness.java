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
 * Value class representing a witness for the multi exponentiation argument.
 * <p>
 * Instances of this class are immutable.
 */
final class MultiExponentiationWitness {

	private final SameGroupMatrix<ZqElement, ZqGroup> A;
	private final SameGroupVector<ZqElement, ZqGroup> r;
	private final ZqElement rho;

	private final ZqGroup group;
	private final int dimensionM;
	private final int dimensionN;

	/**
	 * <p>Create a multi-exponentiation witness.</p>
	 *
	 * Parameters must abide by the following conditions:
	 * <ul>
	 *     <li>must be non null</li>
	 *     <li>must belong to the same ZqGroup</li>
	 * </ul>
	 *
	 * @param matrixA A, the exponents matrix, of size n x m
	 * @param exponentsR r, a vector of exponents of size m
	 * @param exponentRho ρ, the re-encrypting exponent
	 */
	MultiExponentiationWitness(final SameGroupMatrix<ZqElement, ZqGroup> matrixA, final SameGroupVector<ZqElement, ZqGroup> exponentsR,
			final ZqElement exponentRho) {

		//Null checking
		checkNotNull(matrixA);
		checkNotNull(exponentsR);
		checkNotNull(exponentRho);

		//Dimension checking
		checkArgument(matrixA.numColumns() == exponentsR.size(), "The matrix A number of columns must equals the number of exponents.");

		//Group checking
		if(!matrixA.isEmpty()) {
			checkArgument(matrixA.getGroup().equals(exponentsR.getGroup()), "The matrix A and the exponents r must belong to the same group.");
			checkArgument(matrixA.getGroup().equals(exponentRho.getGroup()), "The matrix A and the exponent ρ must belong to the same group");
		}

		this.A = matrixA;
		this.r = exponentsR;
		this.rho = exponentRho;

		this.group = matrixA.getGroup();
		this.dimensionM = matrixA.numColumns();
		this.dimensionN = matrixA.numRows();
	}

	SameGroupMatrix<ZqElement, ZqGroup> getA() {
		return A;
	}

	SameGroupVector<ZqElement, ZqGroup> getR() {
		return r;
	}

	ZqElement getRho() {
		return rho;
	}

	ZqGroup getGroup() {
		return group;
	}

	int getDimensionM() {
		return dimensionM;
	}

	int getDimensionN() {
		return dimensionN;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		MultiExponentiationWitness that = (MultiExponentiationWitness) o;
		return A.equals(that.A) && r.equals(that.r) && rho.equals(that.rho);
	}

	@Override
	public int hashCode() {
		return Objects.hash(A, r, rho);
	}
}
