/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Objects;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;

class ProductArgument {

	private final SingleValueProductArgument singleValueProductArgument;
	private final int n;
	private final GqGroup group;
	private GqElement commitmentB;
	private HadamardArgument hadamardArgument;
	private int m;

	/**
	 * Constructs a ProductArgument.
	 *
	 * @param commitmentB                the commitment to a vector b.
	 * @param hadamardArgument           the Hadamard argument.
	 * @param singleValueProductArgument the Single Value Product argument.
	 */
	ProductArgument(final GqElement commitmentB, final HadamardArgument hadamardArgument,
			final SingleValueProductArgument singleValueProductArgument) {
		this(singleValueProductArgument);
		this.commitmentB = checkNotNull(commitmentB);
		this.hadamardArgument = checkNotNull(hadamardArgument);
		this.m = hadamardArgument.getM();
	}

	ProductArgument(final SingleValueProductArgument singleValueProductArgument) {
		this.singleValueProductArgument = checkNotNull(singleValueProductArgument);
		this.n = singleValueProductArgument.getN();
		this.group = singleValueProductArgument.getGroup();
		this.m = 1;
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

	int getM() {
		return m;
	}

	int getN() {
		return n;
	}

	GqGroup getGroup() {
		return group;
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
		return Objects.equals(commitmentB, that.commitmentB) && Objects.equals(hadamardArgument, that.hadamardArgument)
				&& singleValueProductArgument.equals(that.singleValueProductArgument);
	}

	@Override
	public int hashCode() {
		return Objects.hash(commitmentB, hadamardArgument, singleValueProductArgument);
	}
}
