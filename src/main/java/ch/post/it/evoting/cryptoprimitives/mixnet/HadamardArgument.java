/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Objects;

import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;

class HadamardArgument {

	private final SameGroupVector<GqElement, GqGroup> commitmentsB;
	private final ZeroArgument zeroArgument;
	private final int m;
	private final GqGroup group;

	/**
	 * Constructs a {@code HadamardArgument}.
	 *
	 * @param commitmentsB a {@link SameGroupVector} of {@code GqElements}
	 * @param zeroArgument a {@link ZeroArgument}
	 */
	HadamardArgument(final SameGroupVector<GqElement, GqGroup> commitmentsB, final ZeroArgument zeroArgument) {
		checkNotNull(commitmentsB);
		checkNotNull(zeroArgument);

		checkArgument(commitmentsB.size() == zeroArgument.getM(),
				"The commitments B must be of the same size as the m of the zero argument.");
		checkArgument(commitmentsB.getGroup().equals(zeroArgument.getGroup()),
				"The commitments B must have the same group order as the zero argument.");

		this.commitmentsB = commitmentsB;
		this.zeroArgument = zeroArgument;
		this.group = commitmentsB.getGroup();
		this.m = commitmentsB.size();
	}

	SameGroupVector<GqElement, GqGroup> getCommitmentsB() {
		return commitmentsB;
	}

	ZeroArgument getZeroArgument() {
		return zeroArgument;
	}

	GqGroup getGroup() {
		return group;
	}

	int getM() {
		return m;
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