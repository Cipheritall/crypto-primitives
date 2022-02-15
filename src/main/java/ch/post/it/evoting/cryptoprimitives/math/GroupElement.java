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
package ch.post.it.evoting.cryptoprimitives.math;

import java.math.BigInteger;
import java.util.Objects;

import ch.post.it.evoting.cryptoprimitives.hashing.HashableBigInteger;

/**
 * Representation of a mathematical group element.
 *
 * <p>GroupElements are immutable.
 *
 * @param <G> the type of the mathematical group this group element belongs to.
 */
public abstract class GroupElement<G extends MathematicalGroup<G>> implements GroupVectorElement<G>, HashableBigInteger {

	protected final BigInteger value;
	protected final G group;

	protected GroupElement(final BigInteger value, final G group) {
		this.value = value;
		this.group = group;
	}

	/**
	 * Returns the element value.
	 *
	 * @return element value.
	 */
	public BigInteger getValue() {
		return this.value;
	}

	@Override
	public G getGroup() {
		return this.group;
	}

	@Override
	public int size(){
		return 1;
	}

	@Override
	public boolean equals(final Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		GroupElement<?> that = (GroupElement<?>) o;
		return value.equals(that.value) && group.equals(that.group);
	}

	@Override
	public int hashCode() {
		return Objects.hash(value, group);
	}

	@Override
	public BigInteger toHashableForm() {
		return this.value;
	}
}
