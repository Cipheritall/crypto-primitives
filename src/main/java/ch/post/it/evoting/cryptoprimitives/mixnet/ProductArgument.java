/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Objects;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;

class ProductArgument {

	private final GqElement commitmentB;
	private final HadamardArgument hadamardArgument;
	private final SingleValueProductArgument singleValueProductArgument;

	/**
	 * Constructs a ProductArgument.
	 *
	 * @param commitmentB                the commitment to a vector b.
	 * @param hadamardArgument           the Hadamard argument.
	 * @param singleValueProductArgument the Single Value Product argument.
	 */
	ProductArgument(final GqElement commitmentB, final HadamardArgument hadamardArgument,
			final SingleValueProductArgument singleValueProductArgument) {
		this.commitmentB = checkNotNull(commitmentB);
		this.hadamardArgument = checkNotNull(hadamardArgument);
		this.singleValueProductArgument = checkNotNull(singleValueProductArgument);
	}

	GqElement getCommitmentB() {
		return commitmentB;
	}

	HadamardArgument getHadamardArgument() {
		return hadamardArgument;
	}

	SingleValueProductArgument getSingleValueProductArgument() {
		return singleValueProductArgument;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		ProductArgument that = (ProductArgument) o;
		return commitmentB.equals(that.commitmentB) && hadamardArgument.equals(that.hadamardArgument) && singleValueProductArgument
				.equals(that.singleValueProductArgument);
	}

	@Override
	public int hashCode() {
		return Objects.hash(commitmentB, hadamardArgument, singleValueProductArgument);
	}
}
