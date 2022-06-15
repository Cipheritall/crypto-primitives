/*
 * Copyright 2022 Post CH Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static ch.post.it.evoting.cryptoprimitives.utils.Validations.allEqual;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableList;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GroupVectorElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

/**
 * Collection of the values contained in a zero argument.
 *
 * <p>Instances of this class are immutable. </p>
 */
@SuppressWarnings({ "java:S100", "java:S116", "java:S117" })
public class ZeroArgument implements HashableList {

	private GqElement c_A_0;
	private GqElement c_B_m;
	private GroupVector<GqElement, GqGroup> c_d;
	private GroupVector<ZqElement, ZqGroup> a_prime;
	private GroupVector<ZqElement, ZqGroup> b_prime;
	private ZqElement r_prime;
	private ZqElement s_prime;
	private ZqElement t_prime;

	private int m;
	private int n;
	private GqGroup group;

	private ZeroArgument() {
		// Intentionally left blank.
	}

	public GqElement get_c_A_0() {
		return c_A_0;
	}

	public GqElement get_c_B_m() {
		return c_B_m;
	}

	public GroupVector<GqElement, GqGroup> get_c_d() {
		return c_d;
	}

	public GroupVector<ZqElement, ZqGroup> get_a_prime() {
		return a_prime;
	}

	public GroupVector<ZqElement, ZqGroup> get_b_prime() {
		return b_prime;
	}

	public ZqElement get_r_prime() {
		return r_prime;
	}

	public ZqElement get_s_prime() {
		return s_prime;
	}

	public ZqElement get_t_prime() {
		return t_prime;
	}

	public int get_m() {
		return m;
	}

	int get_n() {
		return n;
	}

	public GqGroup getGroup() {
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
		return c_A_0.equals(that.c_A_0) && c_B_m.equals(that.c_B_m) && c_d.equals(that.c_d) && a_prime.equals(that.a_prime) && b_prime
				.equals(that.b_prime)
				&& r_prime.equals(that.r_prime) && s_prime.equals(that.s_prime) && t_prime.equals(that.t_prime);
	}

	@Override
	public int hashCode() {
		return Objects.hash(c_A_0, c_B_m, c_d, a_prime, b_prime, r_prime, s_prime, t_prime);
	}

	@Override
	public List<? extends Hashable> toHashableForm() {
		return List.of(c_A_0, c_B_m, c_d, a_prime, b_prime, r_prime, s_prime, t_prime);
	}

	/**
	 * Builder to construct a {@link ZeroArgument}.
	 *
	 * <p>Instances of this class are NOT immutable. </p>
	 */
	public static class Builder {

		private GqElement c_A_0;
		private GqElement c_B_m;
		private GroupVector<GqElement, GqGroup> c_d;
		private GroupVector<ZqElement, ZqGroup> a_prime;
		private GroupVector<ZqElement, ZqGroup> b_prime;
		private ZqElement r_prime;
		private ZqElement s_prime;
		private ZqElement t_prime;

		public Builder with_c_A_0(final GqElement c_A_0) {
			this.c_A_0 = c_A_0;
			return this;
		}

		public Builder with_c_B_m(final GqElement c_B_m) {
			this.c_B_m = c_B_m;
			return this;
		}

		public Builder with_c_d(final GroupVector<GqElement, GqGroup> c_d) {
			this.c_d = c_d;
			return this;
		}

		public Builder with_a_prime(final GroupVector<ZqElement, ZqGroup> a_prime) {
			this.a_prime = a_prime;
			return this;
		}

		public Builder with_b_prime(final GroupVector<ZqElement, ZqGroup> b_prime) {
			this.b_prime = b_prime;
			return this;
		}

		public Builder with_r_prime(final ZqElement r_prime) {
			this.r_prime = r_prime;
			return this;
		}

		public Builder with_s_prime(final ZqElement s_prime) {
			this.s_prime = s_prime;
			return this;
		}

		public Builder with_t_prime(final ZqElement t_prime) {
			this.t_prime = t_prime;
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
			checkNotNull(this.c_A_0);
			checkNotNull(this.c_B_m);
			checkNotNull(this.c_d);
			checkNotNull(this.a_prime);
			checkNotNull(this.b_prime);
			checkNotNull(this.r_prime);
			checkNotNull(this.s_prime);
			checkNotNull(this.t_prime);

			// Cross group checking.
			final List<GroupVectorElement<GqGroup>> gqGroupMembers = Arrays.asList(c_A_0, c_B_m, c_d);
			final List<GroupVectorElement<ZqGroup>> zqGroupMembers = Arrays.asList(a_prime, b_prime, r_prime, s_prime, t_prime);
			checkArgument(allEqual(gqGroupMembers.stream(), GroupVectorElement::getGroup), "cA0, cBm, cd must belong to the same group.");
			checkArgument(allEqual(zqGroupMembers.stream(), GroupVectorElement::getGroup),
					"aPrime, bPrime, rPrime, sPrime, tPrime must belong to the same group.");
			checkArgument(c_A_0.getGroup().hasSameOrderAs(a_prime.getGroup()), "GqGroup and ZqGroup of argument inputs are not compatible.");

			// Cross dimensions checking.
			checkArgument(a_prime.size() == b_prime.size(), "The vectors aPrime and bPrime must have the same size.");

			// Dimensions checking.
			checkArgument((c_d.size() - 1) % 2 == 0, "cd must be of size 2m + 1.");

			// Build the argument.
			final ZeroArgument zeroArgument = new ZeroArgument();
			zeroArgument.c_A_0 = this.c_A_0;
			zeroArgument.c_B_m = this.c_B_m;
			zeroArgument.c_d = this.c_d;
			zeroArgument.a_prime = this.a_prime;
			zeroArgument.b_prime = this.b_prime;
			zeroArgument.r_prime = this.r_prime;
			zeroArgument.s_prime = this.s_prime;
			zeroArgument.t_prime = this.t_prime;

			zeroArgument.m = (c_d.size() - 1) / 2;
			zeroArgument.n = a_prime.size();
			zeroArgument.group = c_A_0.getGroup();

			return zeroArgument;
		}
	}

}
