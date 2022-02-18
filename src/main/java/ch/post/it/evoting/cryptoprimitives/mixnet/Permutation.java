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
import java.util.stream.Stream;

import com.google.common.collect.ImmutableList;

/**
 * Represents a permutation of integers in the range [0, N).
 *
 * <p>Instances of this class are immutable.
 */
class Permutation {

	static final Permutation EMPTY = new Permutation(ImmutableList.of());

	//valueMapping[i] represents the permutation of value i
	private final ImmutableList<Integer> valueMapping;
	private final int size;

	Permutation(final ImmutableList<Integer> valueMapping) {
		checkNotNull(valueMapping);

		this.size = valueMapping.size();
		this.valueMapping = valueMapping;
	}

	/**
	 * @return A stream of elements of this permutation.
	 */
	Stream<Integer> stream() {
		return this.valueMapping.stream();
	}

	/**
	 * Gets the new value of value i under this permutation.
	 *
	 * @param i the value to get the permutation of. Must be positive and smaller than the size of this permutation.
	 * @return a value in the range [0, N)
	 */
	int get(final int i) {
		checkArgument(i >= 0);
		checkArgument(i < size);

		return this.valueMapping.get(i);
	}

	/**
	 * @return the size of this permutation, i.e. the upperbound of values represented in this permutation.
	 */
	int size() {
		return this.size;
	}

	@Override
	public boolean equals(final Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		final Permutation that = (Permutation) o;
		return valueMapping.equals(that.valueMapping);
	}

	@Override
	public int hashCode() {
		return Objects.hash(valueMapping);
	}
}
