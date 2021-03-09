/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static ch.post.it.evoting.cryptoprimitives.Validations.allEqual;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import ch.post.it.evoting.cryptoprimitives.GroupVectorElement;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

/**
 * Collection of the values contained in a single value product argument.
 */
class SingleValueProductArgument {

	private GqElement cd;
	private GqElement cLowerDelta;
	private GqElement cUpperDelta;
	private SameGroupVector<ZqElement, ZqGroup> aTilde;
	private SameGroupVector<ZqElement, ZqGroup> bTilde;
	private ZqElement rTilde;
	private ZqElement sTilde;

	private int n;
	private GqGroup group;

	private SingleValueProductArgument() {
		// Intentionally left blank.
	}

	GqElement getCd() {
		return cd;
	}

	GqElement getCLowerDelta() {
		return cLowerDelta;
	}

	GqElement getCUpperDelta() {
		return cUpperDelta;
	}

	SameGroupVector<ZqElement, ZqGroup> getATilde() {
		return aTilde;
	}

	SameGroupVector<ZqElement, ZqGroup> getBTilde() {
		return bTilde;
	}

	ZqElement getRTilde() {
		return rTilde;
	}

	ZqElement getSTilde() {
		return sTilde;
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
		SingleValueProductArgument that = (SingleValueProductArgument) o;
		return cd.equals(that.cd) &&
				cLowerDelta.equals(that.cLowerDelta) &&
				cUpperDelta.equals(that.cUpperDelta) &&
				aTilde.equals(that.aTilde) &&
				bTilde.equals(that.bTilde) &&
				rTilde.equals(that.rTilde) &&
				sTilde.equals(that.sTilde);
	}

	@Override
	public int hashCode() {
		return Objects.hash(cd, cLowerDelta, cUpperDelta, aTilde, bTilde, rTilde, sTilde);
	}

	static class Builder {

		private GqElement cd;
		private GqElement cLowerDelta;
		private GqElement cUpperDelta;
		private SameGroupVector<ZqElement, ZqGroup> aTilde;
		private SameGroupVector<ZqElement, ZqGroup> bTilde;
		private ZqElement rTilde;
		private ZqElement sTilde;

		Builder withCd(final GqElement cd) {
			this.cd = cd;
			return this;
		}

		Builder withCLowerDelta(final GqElement cLowerDelta) {
			this.cLowerDelta = cLowerDelta;
			return this;
		}

		Builder withCUpperDelta(final GqElement cUpperDelta) {
			this.cUpperDelta = cUpperDelta;
			return this;
		}

		Builder withATilde(final SameGroupVector<ZqElement, ZqGroup> aTilde) {
			this.aTilde = aTilde;
			return this;
		}

		Builder withBTilde(final SameGroupVector<ZqElement, ZqGroup> bTilde) {
			this.bTilde = bTilde;
			return this;
		}

		Builder withRTilde(final ZqElement rTilde) {
			this.rTilde = rTilde;
			return this;
		}

		Builder withSTilde(final ZqElement sTilde) {
			this.sTilde = sTilde;
			return this;
		}

		/**
		 * Builds the {@link SingleValueProductArgument}. Upon calling this method, all fields must have be set to non null values.
		 * <p>
		 * Additionally, the fields must comply with the following:
		 * <ul>
		 *     <li>c<sub>d</sub>, c<sub>δ</sub>, c<sub>Δ</sub> must belong to the same GqGroup</li>
		 *     <li>aTilde, bTilde, rTilde, sTilde must belong to the same ZqGroup</li>
		 *     <li>these GqGroup and ZqGroup must have the same order</li>
		 *     <li>vectors aTilde and bTilde must have the same size n greater than or equal to 2</li>
		 * </ul>
		 *
		 * @return A valid Single Value Product Argument.
		 */
		SingleValueProductArgument build() {
			// Null checking.
			checkNotNull(this.cd);
			checkNotNull(this.cLowerDelta);
			checkNotNull(this.cUpperDelta);
			checkNotNull(this.aTilde);
			checkNotNull(this.bTilde);
			checkNotNull(this.rTilde);
			checkNotNull(this.sTilde);

			// Cross group checking.
			final List<GroupVectorElement<GqGroup>> gqGroupMembers = Arrays.asList(cd, cLowerDelta, cUpperDelta);
			final List<GroupVectorElement<ZqGroup>> zqGroupMembers = Arrays.asList(aTilde, bTilde, rTilde, sTilde);
			checkArgument(allEqual(gqGroupMembers.stream(), GroupVectorElement::getGroup),
					"cd, cLowerDelta, cUpperDelta must belong to the same group.");
			checkArgument(allEqual(zqGroupMembers.stream(), GroupVectorElement::getGroup),
					"aTilde, bTilde, rTilde, sTilde must belong to the same group.");
			checkArgument(cd.getGroup().hasSameOrderAs(aTilde.getGroup()), "GqGroup and ZqGroup of argument inputs are not compatible.");

			// Cross dimensions checking.
			checkArgument(aTilde.size() == bTilde.size(), "The vectors aTilde and bTilde must have the same size.");

			// Dimensions checking.
			checkArgument(this.aTilde.size() >= 2, "The size of vectors aTilde and bTilde must be greater than or equal to 2.");

			// Build the argument.
			final SingleValueProductArgument argument = new SingleValueProductArgument();
			argument.cd = this.cd;
			argument.cLowerDelta = this.cLowerDelta;
			argument.cUpperDelta = this.cUpperDelta;
			argument.aTilde = this.aTilde;
			argument.bTilde = this.bTilde;
			argument.rTilde = this.rTilde;
			argument.sTilde = this.sTilde;

			argument.n = argument.aTilde.size();
			argument.group = argument.cd.getGroup();

			return argument;
		}
	}
}
