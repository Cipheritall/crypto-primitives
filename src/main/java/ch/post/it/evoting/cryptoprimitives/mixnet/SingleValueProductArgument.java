/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Objects;

import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
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

	private SingleValueProductArgument() {
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

	static class SingleValueProductArgumentBuilder {

		private GqElement cd;
		private GqElement cLowerDelta;
		private GqElement cUpperDelta;
		private SameGroupVector<ZqElement, ZqGroup> aTilde;
		private SameGroupVector<ZqElement, ZqGroup> bTilde;
		private ZqElement rTilde;
		private ZqElement sTilde;

		SingleValueProductArgumentBuilder() {

		}

		SingleValueProductArgumentBuilder withCd(final GqElement cd) {
			this.cd = cd;
			return this;
		}

		SingleValueProductArgumentBuilder withCLowerDelta(final GqElement cLowerDelta) {
			this.cLowerDelta = cLowerDelta;
			return this;
		}

		SingleValueProductArgumentBuilder withCUpperDelta(final GqElement cUpperDelta) {
			this.cUpperDelta = cUpperDelta;
			return this;
		}

		SingleValueProductArgumentBuilder withATilde(final SameGroupVector<ZqElement, ZqGroup> aTilde) {
			this.aTilde = aTilde;
			return this;
		}

		SingleValueProductArgumentBuilder withBTilde(final SameGroupVector<ZqElement, ZqGroup> bTilde) {
			this.bTilde = bTilde;
			return this;
		}

		SingleValueProductArgumentBuilder withRTilde(final ZqElement rTilde) {
			this.rTilde = rTilde;
			return this;
		}

		SingleValueProductArgumentBuilder withSTilde(final ZqElement sTilde) {
			this.sTilde = sTilde;
			return this;
		}

		SingleValueProductArgument build() {
			SingleValueProductArgument argument = new SingleValueProductArgument();
			argument.cd = checkNotNull(this.cd);
			argument.cLowerDelta = checkNotNull(this.cLowerDelta);
			argument.cUpperDelta = checkNotNull(this.cUpperDelta);
			argument.aTilde = checkNotNull(this.aTilde);
			argument.bTilde = checkNotNull(this.bTilde);
			argument.rTilde = checkNotNull(this.rTilde);
			argument.sTilde = checkNotNull(this.sTilde);

			return argument;
		}
	}
}
