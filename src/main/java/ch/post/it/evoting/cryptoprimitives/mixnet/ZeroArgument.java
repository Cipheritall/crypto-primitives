/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static com.google.common.base.Preconditions.checkNotNull;

import java.util.List;
import java.util.Objects;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;

/**
 * Collection of the values contained in a zero argument.
 */
class ZeroArgument {

	private GqElement cA0;
	private GqElement cBm;
	private List<GqElement> cd;
	private List<ZqElement> aPrime;
	private List<ZqElement> bPrime;
	private ZqElement rPrime;
	private ZqElement sPrime;
	private ZqElement tPrime;

	private ZeroArgument() {
	}

	GqElement getCA0() {
		return cA0;
	}

	GqElement getCBm() {
		return cBm;
	}

	List<GqElement> getCd() {
		return cd;
	}

	List<ZqElement> getAPrime() {
		return aPrime;
	}

	List<ZqElement> getBPrime() {
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
	static class ZeroArgumentBuilder {

		private GqElement cA0;
		private GqElement cBm;
		private List<GqElement> cd;
		private List<ZqElement> aPrime;
		private List<ZqElement> bPrime;
		private ZqElement rPrime;
		private ZqElement sPrime;
		private ZqElement tPrime;

		ZeroArgumentBuilder withCA0(final GqElement cA0) {
			this.cA0 = cA0;
			return this;
		}

		ZeroArgumentBuilder withCBm(final GqElement cBm) {
			this.cBm = cBm;
			return this;
		}

		ZeroArgumentBuilder withCd(final List<GqElement> cd) {
			this.cd = cd;
			return this;
		}

		ZeroArgumentBuilder withAPrime(final List<ZqElement> aPrime) {
			this.aPrime = aPrime;
			return this;
		}

		ZeroArgumentBuilder withBPrime(final List<ZqElement> bPrime) {
			this.bPrime = bPrime;
			return this;
		}

		ZeroArgumentBuilder withRPrime(final ZqElement rPrime) {
			this.rPrime = rPrime;
			return this;
		}

		ZeroArgumentBuilder withSPrime(final ZqElement sPrime) {
			this.sPrime = sPrime;
			return this;
		}

		ZeroArgumentBuilder withTPrime(final ZqElement tPrime) {
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

			return zeroArgument;
		}
	}

}
