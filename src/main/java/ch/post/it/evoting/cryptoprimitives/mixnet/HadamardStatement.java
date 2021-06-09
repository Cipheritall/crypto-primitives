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

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;

@SuppressWarnings({"java:S100", "java:S116", "java:S117"})
class HadamardStatement {

	private final GroupVector<GqElement, GqGroup> c_A;
	private final GqElement c_b;
	private final GqGroup group;
	private final int m;

	/**
	 * Constructs a {@code HadamardStatement} object.
	 * <p>
	 * Both inputs must comply with the following:
	 * <ul>
	 *     <li>be non null</li>
	 *     <li>belong to the same group</li>
	 * </ul>
	 *
	 * @param c_A c<sub>A</sub>, the vectors of commitments to a matrix A
	 * @param c_b  c<sub>b</sub>, the commitment to a vector b.
	 */
	HadamardStatement(final GroupVector<GqElement, GqGroup> c_A, final GqElement c_b) {
		checkNotNull(c_A);
		checkNotNull(c_b);

		this.c_A = c_A;
		this.c_b = c_b;
		this.group = c_A.getGroup();
		this.m = c_A.size();

		checkArgument(this.c_A.getGroup().equals(this.c_b.getGroup()),
				"The commitments A and commitment b must have the same group.");
	}

	GroupVector<GqElement, GqGroup> get_c_A() {
		return c_A;
	}

	GqElement get_c_b() {
		return c_b;
	}

	GqGroup getGroup() {
		return group;
	}

	int get_m() {
		return m;
	}
}
