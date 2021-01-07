/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.math;

import java.math.BigInteger;
import java.util.Objects;

import ch.post.it.evoting.cryptoprimitives.HasGroup;
import ch.post.it.evoting.cryptoprimitives.HashableBigInteger;

/**
 * Representation of a mathematical group element.
 *
 * <p>GroupElements are immutable.
 *
 * @param <G> the type of the mathematical group this group element belongs to.
 */
public abstract class GroupElement<G extends MathematicalGroup<G>> implements HasGroup<G>, HashableBigInteger {

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
	public boolean equals(Object o) {
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
