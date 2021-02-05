/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import java.util.Objects;

import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;

class HadamardArgument {

	private final SameGroupVector<GqElement, GqGroup> commitmentsB;
	private final ZeroArgument zeroArgument;

	/**
	 * Constructs a {@code HadamardArgument}.
	 *
	 * @param commitmentsB a {@link SameGroupVector} of {@code GqElements}
	 * @param zeroArgument a {@link ZeroArgument}
	 */
	HadamardArgument(final SameGroupVector<GqElement, GqGroup> commitmentsB, final ZeroArgument zeroArgument) {
		this.commitmentsB = commitmentsB;
		this.zeroArgument = zeroArgument;
	}

	SameGroupVector<GqElement, GqGroup> getCommitmentsB() {
		return commitmentsB;
	}

	ZeroArgument getZeroArgument() {
		return zeroArgument;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		HadamardArgument that = (HadamardArgument) o;
		return commitmentsB.equals(that.commitmentsB) && zeroArgument.equals(that.zeroArgument);
	}

	@Override
	public int hashCode() {
		return Objects.hash(commitmentsB, zeroArgument);
	}
}
