/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.math;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;

/**
 * Class which defines a Gq group element, ie elements of the quadratic residue group of order q and mod p.
 *
 * <p>Instances of this class are immutable.
 */
public final class GqElement extends GroupElement<GqGroup> {

	// Private constructor without input validation. Used only for operations that provide a mathematical guarantee that the element is within the
	// group (such as multiplying two elements of the same group).
	private GqElement(final BigInteger value, final GqGroup group) {
		super(value, group);
	}

	/**
	 * Creates a {@code GqElement}. The specified value should be an element of the group.
	 *
	 * @param value the value of the element. Must not be null and must be an element of the group.
	 * @param group the {@link GqGroup} to which this element belongs.
	 */
	public static GqElement create(final BigInteger value, final GqGroup group) {
		checkNotNull(value);
		checkNotNull(group);
		checkArgument(group.isGroupMember(value), "Cannot create a GroupElement with value %s as it is not an element of group %s", value, group);

		return new GqElement(value, group);
	}

	/**
	 * Returns a {@code GqElement} whose value is {@code (this * element)}.
	 *
	 * @param other The element to be multiplied by this. It must be from the same group and non null.
	 * @return (this * element).
	 */
	public GqElement multiply(final GqElement other) {
		checkNotNull(other);
		checkArgument(this.group.equals(other.group));

		BigInteger resultValue = BigIntegerOperations.modMultiply(value, other.getValue(), group.getP());
		return new GqElement(resultValue, this.group);
	}

	/**
	 * Returns a {@code GqElement} whose value is (this<sup>exponent</sup>).
	 *
	 * @param exponent the exponent to which this {@code SameGroupElement} is to be raised. It must be a member of a group of the same order and be
	 *                 non null.
	 * @return (this < sup > exponent < / sup >).
	 */
	public GqElement exponentiate(final ZqElement exponent) {
		checkNotNull(exponent);
		checkArgument(isOfSameOrderGroup(exponent));

		BigInteger valueExponentiated = BigIntegerOperations.modPow(value, exponent.getValue(), this.group.getP());
		return new GqElement(valueExponentiated, this.group);
	}

	private boolean isOfSameOrderGroup(final ZqElement exponent) {
		return this.group.getQ().equals(exponent.getGroup().getQ());
	}

	public GqElement invert() {
		BigInteger invertedValue = value.modInverse(this.group.getP());
		return new GqElement(invertedValue, this.group);
	}

	@Override
	public String toString() {
		return "GqElement [value=" + value + "," + group.toString() + "]";
	}
}
