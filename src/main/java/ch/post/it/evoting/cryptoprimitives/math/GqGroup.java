/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.math;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Quadratic residues group of integers modulo p, such that p is a safe prime, i.e. p = 2q + 1. In this case q is the order of the group (ie the
 * number of elements of the group).
 *
 * <p>A group can have multiple generators, which can generate all members of the group through exponentiation.
 *
 * <p>Instances of this class are immutable.
 */
public final class GqGroup implements StreamlinedMathematicalGroup<GqGroup> {

	private final BigInteger p;

	private final BigInteger q;

	private final GqElement generator;

	private final GqElement identity;

	/***
	 * @param p The modulus.
	 * @param q The order of the group.
	 * @param g A generator of the group.
	 *
	 * <p> Preconditions
	 * <li>all arguments are non null</li>
	 * <li>p is prime</li>
	 * <li>q is prime</li>
	 * <li>p = 2q + 1</li>
	 * <li>q is in the range [1, p)</li>
	 * <li>g is in the range [2, p)</li>
	 * <li>g is a member of the group</li>
	 * </p>
	 */
	public GqGroup(final BigInteger p, final BigInteger q, final BigInteger g) {
		checkNotNull(p, "Group Gq parameter p should not be null");
		checkNotNull(q, "Group Gq parameter q should not be null");
		checkNotNull(g, "Group Gq parameter g should not be null");

		//Validate p
		checkArgument(p.isProbablePrime(CertaintyLevel.getCertaintyLevel(p.bitLength())), "Group Gq parameter p must be prime");
		this.p = p;

		//Validate q
		checkArgument(q.isProbablePrime(CertaintyLevel.getCertaintyLevel(q.bitLength())), "Group Gq parameter q must be prime");
		checkArgument(q.compareTo(BigInteger.ZERO) > 0);
		checkArgument(q.compareTo(p) < 0);
		BigInteger computedP = q.multiply(BigInteger.valueOf(2)).add(BigInteger.ONE);
		checkArgument(computedP.equals(p), "Group Gq parameter p must be equal to 2q + 1");
		this.q = q;

		//Validate g
		checkArgument(g.compareTo(BigInteger.ONE) > 0);
		checkArgument(g.compareTo(p) < 0);
		checkArgument(isGroupMember(g), "Group Gq generator g %s must be a member of the group", g);
		generator = GqElement.create(g, this);

		identity = GqElement.create(BigInteger.ONE, this);
	}

	/**
	 * Checks if a value is a member of this group. A given value is a member of this group if:
	 *
	 * <ul>
	 *     <li> the object is non null</li>
	 *   <li>The given value is an integer in (0, p) (exclusive)}
	 *   <li>{@code (value<sup>q</sup> mod p) = 1}
	 * </ul>
	 */
	@Override
	public boolean isGroupMember(final BigInteger value) {
		return value != null &&
				value.compareTo(BigInteger.ZERO) > 0 &&
				value.compareTo(p) < 0 &&
				BigIntegerOperations.modPow(value, q, p).compareTo(BigInteger.ONE) == 0;
	}

	public BigInteger getP() {
		return p;
	}

	public GqElement getGenerator() {
		return generator;
	}

	@Override
	public GqElement getIdentity() {
		return identity;
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
		GqGroup gqGroup = (GqGroup) o;
		return p.equals(gqGroup.p) && q.equals(gqGroup.q) && generator.getValue().equals(gqGroup.generator.getValue());
	}

	@Override
	public int hashCode() {
		return Objects.hash(p, q, generator.getValue());
	}

	@Override
	public String toString() {
		return "Group Gq [p = " + p + ", q = " + q + ", g = " + generator.getValue() + "]";
	}
}