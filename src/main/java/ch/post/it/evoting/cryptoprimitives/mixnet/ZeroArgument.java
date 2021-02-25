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
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

/**
 * Collection of the values contained in a zero argument.
 */
class ZeroArgument {

	private GqElement cA0;
	private GqElement cBm;
	private SameGroupVector<GqElement, GqGroup> cd;
	private SameGroupVector<ZqElement, ZqGroup> aPrime;
	private SameGroupVector<ZqElement, ZqGroup> bPrime;
	private ZqElement rPrime;
	private ZqElement sPrime;
	private ZqElement tPrime;

	private GqGroup group;
	private int m;

	private ZeroArgument() {
	}

	GqElement getCA0() {
		return cA0;
	}

	GqElement getCBm() {
		return cBm;
	}

	SameGroupVector<GqElement, GqGroup> getCd() {
		return cd;
	}

	SameGroupVector<ZqElement, ZqGroup> getAPrime() {
		return aPrime;
	}

	SameGroupVector<ZqElement, ZqGroup> getBPrime() {
		return bPrime;
	}

	ZqElement getRPrime() {
		return rPrime;
	}

	ZqElement getSPrime() {
		return sPrime;
	}

	ZqElement getTPrime() {
		return tPrime;
	}

	int getM() {
		return m;
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
		ZeroArgument that = (ZeroArgument) o;
		return cA0.equals(that.cA0) && cBm.equals(that.cBm) && cd.equals(that.cd) && aPrime.equals(that.aPrime) && bPrime.equals(that.bPrime)
				&& rPrime.equals(that.rPrime) && sPrime.equals(that.sPrime) && tPrime.equals(that.tPrime);
	}

	@Override
	public int hashCode() {
		return Objects.hash(cA0, cBm, cd, aPrime, bPrime, rPrime, sPrime, tPrime);
	}

	/**
	 * Builder to construct a {@link ZeroArgument}.
	 */
	static class Builder {

		private GqElement cA0;
		private GqElement cBm;
		private SameGroupVector<GqElement, GqGroup> cd;
		private SameGroupVector<ZqElement, ZqGroup> aPrime;
		private SameGroupVector<ZqElement, ZqGroup> bPrime;
		private ZqElement rPrime;
		private ZqElement sPrime;
		private ZqElement tPrime;

		Builder withCA0(final GqElement cA0) {
			this.cA0 = cA0;
			return this;
		}

		Builder withCBm(final GqElement cBm) {
			this.cBm = cBm;
			return this;
		}

		Builder withCd(final SameGroupVector<GqElement, GqGroup> cd) {
			this.cd = cd;
			return this;
		}

		Builder withAPrime(final SameGroupVector<ZqElement, ZqGroup> aPrime) {
			this.aPrime = aPrime;
			return this;
		}

		Builder withBPrime(final SameGroupVector<ZqElement, ZqGroup> bPrime) {
			this.bPrime = bPrime;
			return this;
		}

		Builder withRPrime(final ZqElement rPrime) {
			this.rPrime = rPrime;
			return this;
		}

		Builder withSPrime(final ZqElement sPrime) {
			this.sPrime = sPrime;
			return this;
		}

		Builder withTPrime(final ZqElement tPrime) {
			this.tPrime = tPrime;
			return this;
		}

		/**
		 * Build the {@link ZeroArgument}. Upon calling this method, all fields must have be set to non null values.
		 *
		 * @return The built Zero Argument.
		 */
		ZeroArgument build() {
			final ZeroArgument zeroArgument = new ZeroArgument();
			zeroArgument.cA0 = checkNotNull(this.cA0);
			zeroArgument.cBm = checkNotNull(this.cBm);
			zeroArgument.cd = checkNotNull(this.cd);
			zeroArgument.aPrime = checkNotNull(this.aPrime);
			zeroArgument.bPrime = checkNotNull(this.bPrime);
			zeroArgument.rPrime = checkNotNull(this.rPrime);
			zeroArgument.sPrime = checkNotNull(this.sPrime);
			zeroArgument.tPrime = checkNotNull(this.tPrime);

			checkArgument((cd.size() - 1) % 2 == 0, "cd must be of size 2m + 1.");
			zeroArgument.m = (cd.size() - 1) / 2; // cd is of size 2m + 1
			zeroArgument.group = cBm.getGroup();

			return zeroArgument;
		}
	}

}