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

/**
 * Representation of a mathematical group.
 *
 * <p>MathematicalGroups are immutable.
 *
 * @param <G> self type.
 */
public interface MathematicalGroup<G extends MathematicalGroup<G>> {

	/**
	 * Checks whether a given value is a member of this {@code MathematicalGroup}.
	 *
	 * @param value group element to check.
	 * @return true if the value is a member of the group and false otherwise.
	 */
	boolean isGroupMember(final BigInteger value);

	/**
	 * Returns the identity element of the group.
	 *
	 * @return the identity element.
	 */
	GroupElement<G> getIdentity();

	/**
	 * Returns the q parameter, which is the order of the group.
	 *
	 * @return the q (order) parameter.
	 */
	BigInteger getQ();

	/**
	 * Compares mathematical groups based on their order.
	 *
	 * @param other mathematical group
	 * @return true if both mathematical groups are of the same order, false otherwise.
	 */
	default boolean hasSameOrderAs(final MathematicalGroup<?> other) {
		return this.getQ().equals(other.getQ());
	}
}
