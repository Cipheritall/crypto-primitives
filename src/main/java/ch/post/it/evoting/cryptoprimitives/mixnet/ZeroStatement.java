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

import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;

/**
 * Represents the statement for a zero argument, consisting of two commitments and a y value for bilinear mapping.
 */
class ZeroStatement {

	private final GroupVector<GqElement, GqGroup> commitmentsA;
	private final GroupVector<GqElement, GqGroup> commitmentsB;
	private final ZqElement y;

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
	 * @param commitmentsA c<sub>A</sub>, a list of {@link GqElement}s.
	 * @param commitmentsB c<sub>B</sub>, a list of {@link GqElement}s.
	 * @param y            The value defining the bilinear mapping.
	 */
	ZeroStatement(final GroupVector<GqElement, GqGroup> commitmentsA, final GroupVector<GqElement, GqGroup> commitmentsB, final ZqElement y) {
		// Null checking.
		this.commitmentsA = checkNotNull(commitmentsA);
		this.commitmentsB = checkNotNull(commitmentsB);
		this.y = checkNotNull(y);

		// Cross dimension checking.
		checkArgument(this.commitmentsA.size() == this.commitmentsB.size(), "The two commitments vectors must have the same size.");

		// Cross group checking.
		if (!commitmentsA.isEmpty()) {
			final GqGroup group = this.commitmentsA.getGroup();
			checkArgument(group.equals(this.commitmentsB.getGroup()), "The two commitments must be part of the same group.");
			checkArgument(group.hasSameOrderAs(this.y.getGroup()), "The y value group must be of the same order as the group of the commitments.");
		}

	}

	GroupVector<GqElement, GqGroup> getCommitmentsA() {
		return commitmentsA;
	}

	GroupVector<GqElement, GqGroup> getCommitmentsB() {
		return commitmentsB;
	}

	ZqElement getY() {
		return y;
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
		return commitmentsA.equals(that.commitmentsA) && commitmentsB.equals(that.commitmentsB) && y.equals(that.y);
	}

	@Override
	public int hashCode() {
		return Objects.hash(commitmentsA, commitmentsB, y);
	}
}
