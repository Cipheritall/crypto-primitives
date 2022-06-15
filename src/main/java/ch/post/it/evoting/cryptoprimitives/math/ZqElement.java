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

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;

import ch.post.it.evoting.cryptoprimitives.internal.math.BigIntegerOperationsService;

/**
 * Element of the group of integers modulo q.
 *
 * <p> Instances of this class are immutable.</p>
 */
public class ZqElement extends GroupElement<ZqGroup> {

	// Private constructor without input validation. Used only for operations that provide a mathematical guarantee that the element is within the
	// group (such as multiplying two elements of the same group).
	private ZqElement(final BigInteger value, final ZqGroup group) {
		super(value, group);
	}

	/**
	 * Creates a new ZqElement.
	 *
	 * @param value the value of the element. Must not be null and must be an element of the group.
	 * @param group the {@link ZqGroup} to which this element belongs.
	 * @return a new ZqElement.
	 */
	public static ZqElement create(final BigInteger value, final ZqGroup group) {
		checkNotNull(value);
		checkNotNull(group);
		checkArgument(group.isGroupMember(value), "Cannot create a GroupElement with value %s as it is not an element of group %s", value, group);

		return new ZqElement(value, group);
	}

	/**
	 * Creates a new ZqElement.
	 *
	 * @param value the value of the element. Must be an element of the group.
	 * @param group the {@link ZqGroup} to which this element belongs.
	 * @return a new ZqElement.
	 */
	public static ZqElement create(final int value, final ZqGroup group) {
		return create(BigInteger.valueOf(value), group);
	}

	@Override
	public BigInteger getValue() {
		return this.value;
	}

	@Override
	public ZqGroup getGroup() {
		return this.group;
	}

	/**
	 * Returns an {@code ZqElement} whose value is {@code (this + exponent) mod q}.
	 *
	 * @param other the other ZqElement. It must be non null and belong to the same group.
	 * @return {@code (this + exponent) mod q}.
	 */
	public ZqElement add(final ZqElement other) {
		checkNotNull(other);
		checkArgument(this.group.equals(other.group));

		final BigInteger result = this.value.add(other.value).mod(this.group.getQ());
		return new ZqElement(result, this.group);
	}

	/**
	 * Returns an {@code Exponent} whose value is {@code (this - exponent) mod q}.
	 *
	 * @param other the other element to be subtracted from this. It must be non null and belong to the same group.
	 * @return {@code (this - other) mod q}.
	 */
	public ZqElement subtract(final ZqElement other) {
		checkNotNull(other);
		checkArgument(this.group.equals(other.group));

		final BigInteger result = this.value.subtract(other.value).mod(this.group.getQ());
		return new ZqElement(result, this.group);
	}

	/**
	 * Returns an {@code ZqElement} whose value is {@code (this * other) mod q}.
	 *
	 * @param other the other to be multiplied. It must be non null and belong to the same group.
	 * @return {@code (this * other) mod q}.
	 */
	public ZqElement multiply(final ZqElement other) {
		checkNotNull(other);
		checkArgument(this.group.equals(other.group));

		final BigInteger result = BigIntegerOperationsService.modMultiply(value, other.getValue(), this.group.getQ());
		return new ZqElement(result, this.group);
	}

	/**
	 * Returns a {@code ZqElement} whose value is {@code (this ^ exponent) mod q}.
	 *
	 * @param exponent the exponent. It must be non null and non negative.
	 * @return {@code (this ^ exponent) mod q}.
	 */
	public ZqElement exponentiate(final BigInteger exponent) {
		checkNotNull(exponent);
		checkArgument(exponent.compareTo(BigInteger.ZERO) >= 0, "The exponent must be positive.");

		final BigInteger result = BigIntegerOperationsService.modExponentiate(value, exponent, this.group.getQ());
		return new ZqElement(result, this.group);
	}

	/**
	 * Returns an {@code ZqElement} whose value is {@code (-this) mod q}.
	 *
	 * @return {@code (-this mod q)}
	 */
	public ZqElement negate() {
		return new ZqElement(value.negate().mod(this.group.getQ()), this.group);
	}

	@Override
	public String toString() {
		return "ZqElement{" + "value=" + value + ", group=" + group + '}';
	}
}
