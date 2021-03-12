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

import java.util.Objects;

import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;

class HadamardArgument {

	private final SameGroupVector<GqElement, GqGroup> commitmentsB;
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
	 * @param commitmentsB a {@link SameGroupVector} of {@link GqElement}s. Non-null.
	 * @param zeroArgument a {@link ZeroArgument}. Non-null.
	 */
	HadamardArgument(final SameGroupVector<GqElement, GqGroup> commitmentsB, final ZeroArgument zeroArgument) {
		checkNotNull(commitmentsB);
		checkNotNull(zeroArgument);

		checkArgument(commitmentsB.size() == zeroArgument.getM(),
				"The commitments B must be of the same size as the m of the zero argument.");
		checkArgument(commitmentsB.getGroup().equals(zeroArgument.getGroup()),
				"The commitments B must have the same group order as the zero argument.");

		this.commitmentsB = commitmentsB;
		this.zeroArgument = zeroArgument;
		this.m = commitmentsB.size();
		this.n = zeroArgument.getN();
		this.group = commitmentsB.getGroup();
	}

	SameGroupVector<GqElement, GqGroup> getCommitmentsB() {
		return commitmentsB;
	}

	ZeroArgument getZeroArgument() {
		return zeroArgument;
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
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		HadamardArgument that = (HadamardArgument) o;
		return commitmentsB.equals(that.commitmentsB) && zeroArgument.equals(that.zeroArgument);
	}

	@Override
	public int hashCode() {
		return Objects.hash(commitmentsB, zeroArgument);
	}
}
