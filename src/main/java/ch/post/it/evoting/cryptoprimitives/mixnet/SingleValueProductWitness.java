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
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

/**
 * Represents the witness for a single value product argument, consisting of a list of elements and a randomness.
 */
class SingleValueProductWitness {

	private final SameGroupVector<ZqElement, ZqGroup> elements;
	private final ZqElement randomness;

	/**
	 * Instantiates a single value product witness object.
	 *
	 * <p>The elements and randomness passed as arguments must be non null and have the same {@link ZqGroup}.
	 * The list of elements must not contain null elements.</p>
	 *
	 * @param elements   (a<sub>0</sub>, ..., a<sub>n-1</sub>), the vector of elements
	 * @param randomness r, the randomness
	 */
	SingleValueProductWitness(final SameGroupVector<ZqElement, ZqGroup> elements, final ZqElement randomness) {
		this.elements = checkNotNull(elements);
		this.randomness = checkNotNull(randomness);

		checkArgument(this.elements.getGroup().equals(this.randomness.getGroup()),
				"All elements must belong to the same group as the randomness");
	}

	SameGroupVector<ZqElement, ZqGroup> getElements() {
		return elements;
	}

	ZqElement getRandomness() {
		return randomness;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		SingleValueProductWitness that = (SingleValueProductWitness) o;
		return elements.equals(that.elements) &&
				randomness.equals(that.randomness);
	}

	@Override
	public int hashCode() {
		return Objects.hash(elements, randomness);
	}
}
