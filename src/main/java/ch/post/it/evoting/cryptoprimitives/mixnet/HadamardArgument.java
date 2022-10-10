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

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.List;
import java.util.Objects;

import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableList;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;

/**
 * <p>Instances of this class are immutable. </p>
 */
@SuppressWarnings({ "java:S100", "java:S116", "java:S117" })
public final class HadamardArgument implements HashableList {

	private final GroupVector<GqElement, GqGroup> c_b;
	private final ZeroArgument zeroArgument;

	private final int m;
	private final int n;
	private final GqGroup group;

	/**
	 * Constructs a {@code HadamardArgument}.
	 * <p>
	 * The {@code commitmentsB} and {@code zeroArgument} must comply with the following:
	 * <ul>
	 *     <li>the commitments must be of the same size as the zero argument dimension {@code m}</li>
	 *     <li>the commitments and zero argument must belong to the same group</li>
	 * </ul>
	 *
	 * @param c_b          a {@link GroupVector} of {@link GqElement}s. Non-null.
	 * @param zeroArgument a {@link ZeroArgument}. Non-null.
	 */
	public HadamardArgument(final GroupVector<GqElement, GqGroup> c_b, final ZeroArgument zeroArgument) {
		checkNotNull(c_b);
		checkNotNull(zeroArgument);

		checkArgument(c_b.size() == zeroArgument.get_m(),
				"The commitments B must be of the same size as the m of the zero argument.");
		checkArgument(c_b.getGroup().equals(zeroArgument.getGroup()),
				"The commitments B must have the same group order as the zero argument.");

		this.c_b = c_b;
		this.zeroArgument = zeroArgument;
		this.m = c_b.size();
		this.n = zeroArgument.get_n();
		this.group = c_b.getGroup();
	}

	public GroupVector<GqElement, GqGroup> get_c_B() {
		return c_b;
	}

	public ZeroArgument get_zeroArgument() {
		return zeroArgument;
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
		final HadamardArgument that = (HadamardArgument) o;
		return c_b.equals(that.c_b) && zeroArgument.equals(that.zeroArgument);
	}

	@Override
	public int hashCode() {
		return Objects.hash(c_b, zeroArgument);
	}

	@Override
	public List<? extends Hashable> toHashableForm() {
		return List.of(c_b, zeroArgument);
	}
}
