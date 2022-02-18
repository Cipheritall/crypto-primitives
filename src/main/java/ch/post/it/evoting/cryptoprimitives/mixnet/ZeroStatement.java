/*
 * Copyright 2022 Post CH Ltd
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

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Objects;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;

/**
 * Represents the statement for a zero argument, consisting of two commitments and a y value for bilinear mapping.
 *
 * <p>Instances of this class are immutable. </p>
 */
@SuppressWarnings({ "java:S100", "java:S116", "java:S117" })
class ZeroStatement {

	private final GroupVector<GqElement, GqGroup> c_A;
	private final GroupVector<GqElement, GqGroup> c_B;
	private final ZqElement y;
	private final int m;
	private final GqGroup group;

	/**
	 * Instantiate a zero statement. The commitments and y must comply with the following:
	 *
	 * <ul>
	 *     <li>be non null</li>
	 *     <li>commitments must be part of the same group</li>
	 *     <li>commitments must be of same length</li>
	 *     <li>value y must be part of the same group as the commitments</li>
	 * </ul>
	 *
	 * @param c_A c<sub>A</sub>, a non-empty list of {@link GqElement}s.
	 * @param c_B c<sub>B</sub>, a non-empty list of {@link GqElement}s.
	 * @param y   The value defining the bilinear mapping.
	 */
	ZeroStatement(final GroupVector<GqElement, GqGroup> c_A, final GroupVector<GqElement, GqGroup> c_B, final ZqElement y) {
		// Null checking.
		this.c_A = checkNotNull(c_A);
		this.c_B = checkNotNull(c_B);
		this.y = checkNotNull(y);

		// Cross dimension checking.
		checkArgument(this.c_A.size() == this.c_B.size(), "The two commitments vectors must have the same size.");
		this.m = this.c_A.size();
		checkArgument(this.m > 0);

		// Cross group checking.
		this.group = this.c_A.getGroup();
		checkArgument(group.equals(this.c_B.getGroup()), "The two commitments must be part of the same group.");
		checkArgument(group.hasSameOrderAs(this.y.getGroup()), "The y value group must be of the same order as the group of the commitments.");
	}

	GroupVector<GqElement, GqGroup> get_c_A() {
		return c_A;
	}

	GroupVector<GqElement, GqGroup> get_c_B() {
		return c_B;
	}

	ZqElement get_y() {
		return y;
	}

	int get_m() {
		return m;
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
		final ZeroStatement that = (ZeroStatement) o;
		return c_A.equals(that.c_A) && c_B.equals(that.c_B) && y.equals(that.y);
	}

	@Override
	public int hashCode() {
		return Objects.hash(c_A, c_B, y);
	}
}
