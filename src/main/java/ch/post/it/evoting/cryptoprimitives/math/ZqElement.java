/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.math;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;

/**
 * Element of the group of integers modulo q.
 *
 * <p> Instances of this class are immutable.</p>
 */
public class ZqElement extends StreamlinedGroupElement<ZqGroup> {

	// Private constructor without input validation. Used only for operations that provide a mathematical guarantee that the element is within the
	// group (such as multiplying two elements of the same group).
	private ZqElement(final BigInteger value, final ZqGroup group) {
		super(value, group);
	}

	/**
	 * Create a new ZqElement.
	 *
	 * @param value the value of the element.
	 * @param group the group this element belongs to.
	 * @return a new ZqElement.
	 */
	public static ZqElement create(final BigInteger value, final ZqGroup group) {
		checkNotNull(value);
		checkNotNull(group);
		checkArgument(group.isGroupMember(value), "Cannot create a GroupElement with value %s as it is not an element of group %s", value, group);

		return new ZqElement(value, group);
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

		BigInteger result = this.value.add(other.value).mod(this.group.getQ());
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

		BigInteger result = this.value.subtract(other.value).mod(this.group.getQ());
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

		BigInteger result = BigIntegerOperations.modMultiply(value, other.getValue(), this.group.getQ());
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
