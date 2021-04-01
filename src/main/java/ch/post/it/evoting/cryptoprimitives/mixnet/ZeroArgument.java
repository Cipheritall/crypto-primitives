/*
 * Copyright 2021 Post CH Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static ch.post.it.evoting.cryptoprimitives.Validations.allEqual;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.GroupVectorElement;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

/**
 * Collection of the values contained in a zero argument.
 */
public class ZeroArgument {

	private GqElement cA0;
	private GqElement cBm;
	private GroupVector<GqElement, GqGroup> cd;
	private GroupVector<ZqElement, ZqGroup> aPrime;
	private GroupVector<ZqElement, ZqGroup> bPrime;
	private ZqElement rPrime;
	private ZqElement sPrime;
	private ZqElement tPrime;

	private int m;
	private int n;
	private GqGroup group;

	private ZeroArgument() {
		// Intentionally left blank.
	}

	GqElement getCA0() {
		return cA0;
	}

	GqElement getCBm() {
		return cBm;
	}

	GroupVector<GqElement, GqGroup> getCd() {
		return cd;
	}

	GroupVector<ZqElement, ZqGroup> getAPrime() {
		return aPrime;
	}

	GroupVector<ZqElement, ZqGroup> getBPrime() {
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

	int getN() {
		return n;
	}

	GqGroup getGroup() {
		return group;
	}

	@Override
	public boolean equals(final Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		final ZeroArgument that = (ZeroArgument) o;
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
	public static class Builder {

		private GqElement cA0;
		private GqElement cBm;
		private GroupVector<GqElement, GqGroup> cd;
		private GroupVector<ZqElement, ZqGroup> aPrime;
		private GroupVector<ZqElement, ZqGroup> bPrime;
		private ZqElement rPrime;
		private ZqElement sPrime;
		private ZqElement tPrime;

		public Builder withCA0(final GqElement cA0) {
			this.cA0 = cA0;
			return this;
		}

		public Builder withCBm(final GqElement cBm) {
			this.cBm = cBm;
			return this;
		}

		public Builder withCd(final GroupVector<GqElement, GqGroup> cd) {
			this.cd = cd;
			return this;
		}

		public Builder withAPrime(final GroupVector<ZqElement, ZqGroup> aPrime) {
			this.aPrime = aPrime;
			return this;
		}

		public Builder withBPrime(final GroupVector<ZqElement, ZqGroup> bPrime) {
			this.bPrime = bPrime;
			return this;
		}

		public Builder withRPrime(final ZqElement rPrime) {
			this.rPrime = rPrime;
			return this;
		}

		public Builder withSPrime(final ZqElement sPrime) {
			this.sPrime = sPrime;
			return this;
		}

		public Builder withTPrime(final ZqElement tPrime) {
			this.tPrime = tPrime;
			return this;
		}

		/**
		 * Builds the {@link ZeroArgument}. Upon calling this method, all fields must have be set to non null values.
		 * <p>
		 * Additionally the fields must comply with the following:
		 * <ul>
		 *     <li>cA0, cBm, cd must belong to the same GqGroup</li>
		 *     <li>aPrime, bPrime, rPrime, sPrime, tPrime must belong to the same ZqGroup</li>
		 *     <li>these GqGroup and ZqGroup must have the same order</li>
		 *     <li>vectors aPrime and bPrime must have the same size</li>
		 * </ul>
		 *
		 * @return A valid Zero Argument.
		 */
		public ZeroArgument build() {
			// Null checking.
			checkNotNull(this.cA0);
			checkNotNull(this.cBm);
			checkNotNull(this.cd);
			checkNotNull(this.aPrime);
			checkNotNull(this.bPrime);
			checkNotNull(this.rPrime);
			checkNotNull(this.sPrime);
			checkNotNull(this.tPrime);

			// Cross group checking.
			final List<GroupVectorElement<GqGroup>> gqGroupMembers = Arrays.asList(cA0, cBm, cd);
			final List<GroupVectorElement<ZqGroup>> zqGroupMembers = Arrays.asList(aPrime, bPrime, rPrime, sPrime, tPrime);
			checkArgument(allEqual(gqGroupMembers.stream(), GroupVectorElement::getGroup), "cA0, cBm, cd must belong to the same group.");
			checkArgument(allEqual(zqGroupMembers.stream(), GroupVectorElement::getGroup),
					"aPrime, bPrime, rPrime, sPrime, tPrime must belong to the same group.");
			checkArgument(cA0.getGroup().hasSameOrderAs(aPrime.getGroup()), "GqGroup and ZqGroup of argument inputs are not compatible.");

			// Cross dimensions checking.
			checkArgument(aPrime.size() == bPrime.size(), "The vectors aPrime and bPrime must have the same size.");

			// Dimensions checking.
			checkArgument((cd.size() - 1) % 2 == 0, "cd must be of size 2m + 1.");

			// Build the argument.
			final ZeroArgument zeroArgument = new ZeroArgument();
			zeroArgument.cA0 = this.cA0;
			zeroArgument.cBm = this.cBm;
			zeroArgument.cd = this.cd;
			zeroArgument.aPrime = this.aPrime;
			zeroArgument.bPrime = this.bPrime;
			zeroArgument.rPrime = this.rPrime;
			zeroArgument.sPrime = this.sPrime;
			zeroArgument.tPrime = this.tPrime;

			zeroArgument.m = (cd.size() - 1) / 2;
			zeroArgument.n = aPrime.size();
			zeroArgument.group = cA0.getGroup();

			return zeroArgument;
		}
	}

}
