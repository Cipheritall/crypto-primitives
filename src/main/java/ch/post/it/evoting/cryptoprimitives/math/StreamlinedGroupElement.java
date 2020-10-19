/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.math;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Representation of a mathematical group element.
 *
 * <p>GroupElements are immutable.
 *
 * @param <G> the type of the mathematical group this group element belongs to.
 */
public abstract class StreamlinedGroupElement<G extends StreamlinedMathematicalGroup<G>> {

	protected final BigInteger value;
	protected final G group;

	protected StreamlinedGroupElement(final BigInteger value, final G group) {
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

	/**
	 * Returns the element's group.
	 *
	 * @return the group this element belongs to.
	 */
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
		StreamlinedGroupElement<?> that = (StreamlinedGroupElement<?>) o;
		return value.equals(that.value) && group.equals(that.group);
	}

	@Override
	public int hashCode() {
		return Objects.hash(value, group);
	}
}
