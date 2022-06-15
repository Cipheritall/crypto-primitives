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
 * Collection of the values contained in a single value product argument.
 *
 * <p>Instances of this class are immutable.</p>
 */
@SuppressWarnings({ "java:S100", "java:S116", "java:S117", "java:S1845", "java:S107" })
public class SingleValueProductArgument implements HashableList {

	private final GqElement c_d;
	private final GqElement c_delta;
	private final GqElement c_Delta;
	private final GroupVector<ZqElement, ZqGroup> a_tilde;
	private final GroupVector<ZqElement, ZqGroup> b_tilde;
	private final ZqElement r_tilde;
	private final ZqElement s_tilde;

	private final int n;
	private final GqGroup group;

	private SingleValueProductArgument(final GqElement c_d, final GqElement c_delta, final GqElement c_Delta,
			final GroupVector<ZqElement, ZqGroup> a_tilde, final GroupVector<ZqElement, ZqGroup> b_tilde, final ZqElement r_tilde,
			final ZqElement s_tilde, final int n, final GqGroup group) {
		this.c_d = c_d;
		this.c_delta = c_delta;
		this.c_Delta = c_Delta;
		this.a_tilde = a_tilde;
		this.b_tilde = b_tilde;
		this.r_tilde = r_tilde;
		this.s_tilde = s_tilde;

		this.n = n;
		this.group = group;
	}

	public GqElement get_c_d() {
		return c_d;
	}

	public GqElement get_c_delta() {
		return c_delta;
	}

	public GqElement get_c_Delta() {
		return c_Delta;
	}

	public GroupVector<ZqElement, ZqGroup> get_a_tilde() {
		return a_tilde;
	}

	public GroupVector<ZqElement, ZqGroup> get_b_tilde() {
		return b_tilde;
	}

	public ZqElement get_r_tilde() {
		return r_tilde;
	}

	public ZqElement get_s_tilde() {
		return s_tilde;
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
		final SingleValueProductArgument that = (SingleValueProductArgument) o;
		return c_d.equals(that.c_d) &&
				c_delta.equals(that.c_delta) &&
				c_Delta.equals(that.c_Delta) &&
				a_tilde.equals(that.a_tilde) &&
				b_tilde.equals(that.b_tilde) &&
				r_tilde.equals(that.r_tilde) &&
				s_tilde.equals(that.s_tilde);
	}

	@Override
	public int hashCode() {
		return Objects.hash(c_d, c_delta, c_Delta, a_tilde, b_tilde, r_tilde, s_tilde);
	}

	@Override
	public List<? extends Hashable> toHashableForm() {
		return List.of(c_d, c_delta, c_Delta, a_tilde, b_tilde, r_tilde, s_tilde);
	}

	/**
	 * <p>Instances of this class are NOT immutable.</p>
	 */
	public static class Builder {

		private GqElement c_d;
		private GqElement c_delta;
		private GqElement c_Delta;
		private GroupVector<ZqElement, ZqGroup> a_tilde;
		private GroupVector<ZqElement, ZqGroup> b_tilde;
		private ZqElement r_tilde;
		private ZqElement s_tilde;

		public Builder with_c_d(final GqElement c_d) {
			this.c_d = c_d;
			return this;
		}

		public Builder with_c_delta(final GqElement c_delta) {
			this.c_delta = c_delta;
			return this;
		}

		public Builder with_c_Delta(final GqElement c_Delta) {
			this.c_Delta = c_Delta;
			return this;
		}

		public Builder with_a_tilde(final GroupVector<ZqElement, ZqGroup> a_tilde) {
			this.a_tilde = a_tilde;
			return this;
		}

		public Builder with_b_tilde(final GroupVector<ZqElement, ZqGroup> b_tilde) {
			this.b_tilde = b_tilde;
			return this;
		}

		public Builder with_r_tilde(final ZqElement r_tilde) {
			this.r_tilde = r_tilde;
			return this;
		}

		public Builder with_s_tilde(final ZqElement s_tilde) {
			this.s_tilde = s_tilde;
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
		public SingleValueProductArgument build() {
			// Null checking.
			checkNotNull(this.c_d);
			checkNotNull(this.c_delta);
			checkNotNull(this.c_Delta);
			checkNotNull(this.a_tilde);
			checkNotNull(this.b_tilde);
			checkNotNull(this.r_tilde);
			checkNotNull(this.s_tilde);

			// Cross group checking.
			final List<GqElement> gqGroupMembers = List.of(c_d, c_delta, c_Delta);
			final List<GroupVectorElement<ZqGroup>> zqGroupMembers = List.of(a_tilde, b_tilde, r_tilde, s_tilde);
			checkArgument(allEqual(gqGroupMembers.stream(), GroupVectorElement::getGroup),
					"cd, cLowerDelta, cUpperDelta must belong to the same group.");
			checkArgument(allEqual(zqGroupMembers.stream(), GroupVectorElement::getGroup),
					"aTilde, bTilde, rTilde, sTilde must belong to the same group.");
			checkArgument(c_d.getGroup().hasSameOrderAs(a_tilde.getGroup()), "GqGroup and ZqGroup of argument inputs are not compatible.");

			// Cross dimensions checking.
			checkArgument(a_tilde.size() == b_tilde.size(), "The vectors aTilde and bTilde must have the same size.");

			// Dimensions checking.
			checkArgument(this.a_tilde.size() >= 2, "The size of vectors aTilde and bTilde must be greater than or equal to 2.");

			// Build the argument.
			return new SingleValueProductArgument(c_d, c_delta, c_Delta, a_tilde, b_tilde, r_tilde, s_tilde, a_tilde.size(), c_d.getGroup());

		}
	}
}
