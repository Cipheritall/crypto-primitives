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

import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;

class HadamardStatement {

	private final SameGroupVector<GqElement, GqGroup> commitmentsA;
	private final GqElement commitmentB;
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
	 * @param commitmentsA c<sub>A</sub>, the vectors of commitments to a matrix A
	 * @param commitmentB  c<sub>b</sub>, the commitment to a vector b.
	 */
	HadamardStatement(final SameGroupVector<GqElement, GqGroup> commitmentsA, final GqElement commitmentB) {
		checkNotNull(commitmentsA);
		checkNotNull(commitmentB);

		this.commitmentsA = commitmentsA;
		this.commitmentB = commitmentB;
		this.group = commitmentsA.getGroup();
		this.m = commitmentsA.size();

		checkArgument(this.commitmentsA.getGroup().equals(this.commitmentB.getGroup()),
				"The commitments A and commitment b must have the same group.");
	}

	SameGroupVector<GqElement, GqGroup> getCommitmentsA() {
		return commitmentsA;
	}

	GqElement getCommitmentB() {
		return commitmentB;
	}

	GqGroup getGroup() {
		return group;
	}

	int getM() {
		return m;
	}
}
