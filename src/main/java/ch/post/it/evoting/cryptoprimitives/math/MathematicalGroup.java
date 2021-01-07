/*
 * HEADER_LICENSE_OPEN_SOURCE
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
	boolean isGroupMember(BigInteger value);

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
	 * Compare mathematical groups based on order.
	 * @param other mathematical group
	 * @return true if both mathematical groups are of the same order, false otherwise.
	 */
	default boolean hasSameOrderAs(MathematicalGroup<?> other) {
		return this.getQ().equals(other.getQ());
	}
}
