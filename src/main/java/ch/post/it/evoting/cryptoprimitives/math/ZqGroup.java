/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.math;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Group of integers modulo q.
 *
 * <p> Instances of this class are immutable.</p>
 */
public class ZqGroup implements MathematicalGroup<ZqGroup> {
	private final BigInteger q;
	private final ZqElement identity;

	public ZqGroup(final BigInteger q) {
		checkNotNull(q);
		checkArgument(q.compareTo(BigInteger.ONE) >= 0);

		this.q = q;
		this.identity = ZqElement.create(BigInteger.ZERO, this);
	}

	/**
	 * Create a ZqGroup with the same order as the given {@link GqGroup};
	 */
	public static ZqGroup sameOrderAs(final GqGroup gqGroup) {
		checkNotNull(gqGroup);
		return new ZqGroup(gqGroup.getQ());
	}

	@Override
	public boolean isGroupMember(final BigInteger value) {
		return value != null && value.compareTo(BigInteger.ZERO) >= 0 && value.compareTo(this.q) < 0;
	}

	@Override
	public ZqElement getIdentity() {
		return this.identity;
	}

	@Override
	public BigInteger getQ() {
		return this.q;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		ZqGroup zqGroup = (ZqGroup) o;
		return q.equals(zqGroup.q);
	}

	@Override
	public int hashCode() {
		return Objects.hash(q);
	}

	@Override
	public String toString() {
		return "ZqGroup{" + "q=" + q + '}';
	}
}
