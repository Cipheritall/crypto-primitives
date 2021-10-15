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

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.GroupVectorElement;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableList;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

/**
 * Value class representing the result of a multi exponentiation proof.
 *
 * <p>Instances of this class are immutable.</p>
 */
@SuppressWarnings({ "java:S100", "java:S116", "java:S117", "java:S107" })
public class MultiExponentiationArgument implements HashableList {

	private final GqElement c_A_0;
	private final GroupVector<GqElement, GqGroup> c_B;
	private final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> E;
	private final GroupVector<ZqElement, ZqGroup> a;
	private final ZqElement r;
	private final ZqElement b;
	private final ZqElement s;
	private final ZqElement tau;

	private final int m;
	private final int n;
	private final int l;
	private final GqGroup group;

	private MultiExponentiationArgument(final GqElement c_A_0, final GroupVector<GqElement, GqGroup> c_B,
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> E, final GroupVector<ZqElement, ZqGroup> a, final ZqElement r,
			final ZqElement b, final ZqElement s, final ZqElement tau, final int m, final int n, final int l, final GqGroup group) {
		this.c_A_0 = c_A_0;
		this.c_B = c_B;
		this.E = E;
		this.a = a;
		this.r = r;
		this.b = b;
		this.s = s;
		this.tau = tau;
		this.m = m;
		this.n = n;
		this.l = l;
		this.group = group;
	}

	GqElement getc_A_0() {
		return c_A_0;
	}

	GroupVector<GqElement, GqGroup> get_c_B() {
		return c_B;
	}

	GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> get_E() {
		return E;
	}

	GroupVector<ZqElement, ZqGroup> get_a() {
		return a;
	}

	ZqElement get_r() {
		return r;
	}

	ZqElement get_b() {
		return b;
	}

	ZqElement get_s() {
		return s;
	}

	ZqElement get_tau() {
		return tau;
	}

	int get_m() {
		return m;
	}

	int get_n() {
		return n;
	}

	int get_l() {
		return l;
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

		final MultiExponentiationArgument that = (MultiExponentiationArgument) o;
		return c_A_0.equals(that.c_A_0) && c_B.equals(that.c_B) && E.equals(that.E) && a.equals(that.a)
				&& r.equals(that.r) && b.equals(that.b) && s.equals(that.s) && tau.equals(that.tau);
	}

	@Override
	public int hashCode() {
		return Objects.hash(c_A_0, c_B, E, a, r, b, s, tau);
	}

	@Override
	public ImmutableList<? extends Hashable> toHashableForm() {
		return ImmutableList.of(c_A_0, c_B, E, a, r, b, s, tau);
	}

	public static class Builder {

		private GqElement c_A_0;
		private GroupVector<GqElement, GqGroup> c_B;
		private GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> E;
		private GroupVector<ZqElement, ZqGroup> a;
		private ZqElement r;
		private ZqElement b;
		private ZqElement s;
		private ZqElement tau;

		public Builder() {
			//Intentionally left blank
		}

		public Builder with_c_A_0(final GqElement c_A_0) {
			this.c_A_0 = c_A_0;
			return this;
		}

		public Builder with_c_B(final GroupVector<GqElement, GqGroup> c_B) {
			this.c_B = c_B;
			return this;
		}

		public Builder with_E(final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> E) {
			this.E = E;
			return this;
		}

		public Builder with_a(final GroupVector<ZqElement, ZqGroup> a) {
			this.a = a;
			return this;
		}

		public Builder with_r(final ZqElement r) {
			this.r = r;
			return this;
		}

		public Builder with_b(final ZqElement b) {
			this.b = b;
			return this;
		}

		public Builder with_s(final ZqElement s) {
			this.s = s;
			return this;
		}

		public Builder with_tau(final ZqElement tau) {
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
		public MultiExponentiationArgument build() {
			// Null checking.
			checkNotNull(this.c_A_0);
			checkNotNull(this.c_B);
			checkNotNull(this.E);
			checkNotNull(this.a);
			checkNotNull(this.r);
			checkNotNull(this.b);
			checkNotNull(this.s);
			checkNotNull(this.tau);

			// Cross group checking.
			final List<GroupVectorElement<GqGroup>> gqGroups = Arrays.asList(c_A_0, c_B, E);
			final List<GroupVectorElement<ZqGroup>> zqGroups = Arrays.asList(a, r, b, s, tau);
			checkArgument(allEqual(gqGroups.stream(), GroupVectorElement::getGroup),
					"cA0, cBVector, EVector must belong to the same group.");
			checkArgument(allEqual(zqGroups.stream(), GroupVectorElement::getGroup), "aVector, r, b, s, tau, must belong to the same group.");
			checkArgument(c_A_0.getGroup().hasSameOrderAs(a.getGroup()), "GqGroup and ZqGroup of argument inputs are not compatible.");

			// Cross dimensions checking.
			checkArgument(c_B.size() == E.size(), "The vectors cB and E must have the same size.");

			// Dimensions checking.
			checkArgument(this.c_B.size() % 2 == 0, "cB and E must be of size 2 * m.");

			// Build the argument.
			return new MultiExponentiationArgument(this.c_A_0, this.c_B, this.E, this.a, this.r, this.b, this.s,
					this.tau, this.c_B.size() / 2, this.a.size(), this.E.getElementSize(), c_A_0.getGroup());

		}
	}
}
