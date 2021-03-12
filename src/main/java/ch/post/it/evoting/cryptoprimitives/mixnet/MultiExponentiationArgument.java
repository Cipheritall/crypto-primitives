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
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

/**
 * Value class representing the result of a multi exponentiation proof.
 */
public class MultiExponentiationArgument {

	private GqElement cA0;
	private GroupVector<GqElement, GqGroup> cBVector;
	private GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> EVector;
	private GroupVector<ZqElement, ZqGroup> aVector;
	private ZqElement r;
	private ZqElement b;
	private ZqElement s;
	private ZqElement tau;

	private int m;
	private int n;
	private int l;
	private GqGroup group;

	private MultiExponentiationArgument() {
		// Intentionally left blank.
	}

	public GqElement getcA0() {
		return cA0;
	}

	public GroupVector<GqElement, GqGroup> getcBVector() {
		return cBVector;
	}

	public GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> getEVector() {
		return EVector;
	}

	public GroupVector<ZqElement, ZqGroup> getaVector() {
		return aVector;
	}

	public ZqElement getR() {
		return r;
	}

	public ZqElement getB() {
		return b;
	}

	public ZqElement getS() {
		return s;
	}

	public ZqElement getTau() {
		return tau;
	}

	int getM() {
		return m;
	}

	int getN() {
		return n;
	}

	int getL() {
		return l;
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

		MultiExponentiationArgument that = (MultiExponentiationArgument) o;
		return cA0.equals(that.cA0) && cBVector.equals(that.cBVector) && EVector.equals(that.EVector) && aVector.equals(that.aVector)
				&& r.equals(that.r) && b.equals(that.b) && s.equals(that.s) && tau.equals(that.tau);
	}

	@Override
	public int hashCode() {
		return Objects.hash(cA0, cBVector, EVector, aVector, r, b, s, tau);
	}

	static class Builder {

		private GqElement cA0;
		private GroupVector<GqElement, GqGroup> cBVector;
		private GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> EVector;
		private GroupVector<ZqElement, ZqGroup> aVector;
		private ZqElement r;
		private ZqElement b;
		private ZqElement s;
		private ZqElement tau;

		Builder() {
			//Intentionally left blank
		}

		Builder withcA0(final GqElement cA0) {
			this.cA0 = cA0;
			return this;
		}

		Builder withcBVector(final GroupVector<GqElement, GqGroup> cBVector) {
			this.cBVector = cBVector;
			return this;
		}

		Builder withEVector(final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> EVector) {
			this.EVector = EVector;
			return this;
		}

		Builder withaVector(final GroupVector<ZqElement, ZqGroup> aVector) {
			this.aVector = aVector;
			return this;
		}

		Builder withr(final ZqElement r) {
			this.r = r;
			return this;
		}

		Builder withb(final ZqElement b) {
			this.b = b;
			return this;
		}

		Builder withs(final ZqElement s) {
			this.s = s;
			return this;
		}

		Builder withtau(final ZqElement tau) {
			this.tau = tau;
			return this;
		}

		/**
		 * Builds the {@link MultiExponentiationArgument}. Upon calling this method, all fields must have been set to non null values.
		 * <p>
		 * Additionally, the fields must comply with the following:
		 * <ul>
		 *     <li>cA0, cBVector, EVector, aVector must belong to the same GqGroup</li>
		 *     <li>r, b, s, tau, must belong to the same ZqGroup</li>
		 *     <li>GqGroup and ZqGroup must have the same order</li>
		 *     <li>cB and E must have the same size</li>
		 * </ul>
		 *
		 * @return A valid Multi Exponentiation Argument.
		 */
		MultiExponentiationArgument build() {
			// Null checking.
			checkNotNull(this.cA0);
			checkNotNull(this.cBVector);
			checkNotNull(this.EVector);
			checkNotNull(this.aVector);
			checkNotNull(this.r);
			checkNotNull(this.b);
			checkNotNull(this.s);
			checkNotNull(this.tau);

			// Cross group checking.
			final List<GroupVectorElement<GqGroup>> gqGroups = Arrays.asList(cA0, cBVector, EVector);
			final List<GroupVectorElement<ZqGroup>> zqGroups = Arrays.asList(aVector, r, b, s, tau);
			checkArgument(allEqual(gqGroups.stream(), GroupVectorElement::getGroup),
					"cA0, cBVector, EVector must belong to the same group.");
			checkArgument(allEqual(zqGroups.stream(), GroupVectorElement::getGroup), "aVector, r, b, s, tau, must belong to the same group.");
			checkArgument(cA0.getGroup().hasSameOrderAs(aVector.getGroup()), "GqGroup and ZqGroup of argument inputs are not compatible.");

			// Cross dimensions checking.
			checkArgument(cBVector.size() == EVector.size(), "The vectors cB and E must have the same size.");

			// Dimensions checking.
			checkArgument(this.cBVector.size() % 2 == 0, "cB and E must be of size 2 * m.");

			// Build the argument.
			final MultiExponentiationArgument argument = new MultiExponentiationArgument();
			argument.cA0 = this.cA0;
			argument.cBVector = this.cBVector;
			argument.EVector = this.EVector;
			argument.aVector = this.aVector;
			argument.r = this.r;
			argument.b = this.b;
			argument.s = this.s;
			argument.tau = this.tau;

			argument.m = this.cBVector.size() / 2;
			argument.n = this.aVector.size();
			argument.l = this.EVector.getElementSize();
			argument.group = cA0.getGroup();

			return argument;
		}
	}
}
