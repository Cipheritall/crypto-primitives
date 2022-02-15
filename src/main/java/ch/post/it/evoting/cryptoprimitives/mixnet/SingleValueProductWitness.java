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

import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

/**
 * Represents the witness for a single value product argument, consisting of a list of elements and a randomness.
 *
 * <p>Instances of this class are immutable.</p>
 */
@SuppressWarnings("java:S100")
class SingleValueProductWitness {

	private final GroupVector<ZqElement, ZqGroup> a;
	private final ZqElement r;

	/**
	 * Instantiates a single value product witness object.
	 *
	 * <p>The elements and randomness passed as arguments must be non null and have the same {@link ZqGroup}.
	 * The list of elements must not contain null elements.</p>
	 *
	 * @param a   (a<sub>0</sub>, ..., a<sub>n-1</sub>), the vector of elements
	 * @param r r, the randomness
	 */
	SingleValueProductWitness(final GroupVector<ZqElement, ZqGroup> a, final ZqElement r) {
		this.a = checkNotNull(a);
		this.r = checkNotNull(r);

		checkArgument(this.a.getGroup().equals(this.r.getGroup()),
				"All elements must belong to the same group as the randomness");
	}

	GroupVector<ZqElement, ZqGroup> get_a() {
		return a;
	}

	ZqElement get_r() {
		return r;
	}

	@Override
	public boolean equals(final Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		final SingleValueProductWitness that = (SingleValueProductWitness) o;
		return a.equals(that.a) &&
				r.equals(that.r);
	}

	@Override
	public int hashCode() {
		return Objects.hash(a, r);
	}
}
