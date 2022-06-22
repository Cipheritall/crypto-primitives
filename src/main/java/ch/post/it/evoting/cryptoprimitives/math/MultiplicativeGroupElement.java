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
package ch.post.it.evoting.cryptoprimitives.math;

import java.math.BigInteger;

/**
 * Representation of a multiplicative {@code GroupElement}.
 *
 * <p>Classes extending MultiplicativeGroupElement should be made immutable.
 */
public abstract class MultiplicativeGroupElement extends GroupElement<GqGroup> {

	protected MultiplicativeGroupElement(final BigInteger value, final GqGroup group) {
		super(value, group);
	}

	/**
	 * Returns a {@code MultiplicativeGroupElement} whose value is {@code (this * element)}.
	 *
	 * @param other The element to be multiplied by this. It must be from the same group and non-null.
	 * @return (this * element).
	 */
	public abstract MultiplicativeGroupElement multiply(final MultiplicativeGroupElement other);

	/**
	 * Returns a {@code MultiplicativeGroupElement} whose value is (this<sup>exponent</sup>).
	 *
	 * @param exponent the exponent to which this {@code SameGroupElement} is to be raised. It must be a member of a group of the same order and be
	 *                 non-null.
	 * @return this<sup>exponent</sup>.
	 */
	public abstract MultiplicativeGroupElement exponentiate(final ZqElement exponent);
}
