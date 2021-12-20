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

import static ch.post.it.evoting.cryptoprimitives.math.GqElement.GqElementFactory;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.Objects;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.SecurityLevel;
import ch.post.it.evoting.cryptoprimitives.SecurityLevelConfig;
import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableBigInteger;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableList;

/**
 * Quadratic residues group of integers modulo p, such that p is a safe prime, i.e. p = 2q + 1. In this case q is the order of the group (ie the
 * number of elements of the group).
 *
 * <p>A group can have multiple generators, which can generate all members of the group through exponentiation.
 *
 * <p>Instances of this class are immutable.
 */
public final class GqGroup implements MathematicalGroup<GqGroup>, HashableList {

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
	 *             <ul>
	 *           		<li>all arguments are non null</li>
	 * 					<li>p is prime</li>
	 *     				<li>q is prime</li>
	 * 					<li>p = 2q + 1</li>
	 * 					<li>q is in the range [1, p)</li>
	 * 					<li>g is in the range [2, p)</li>
	 * 					<li>g is a member of the group</li>
	 * 				</ul>
	 */
	public GqGroup(final BigInteger p, final BigInteger q, final BigInteger g) {
		checkNotNull(p, "Group Gq parameter p should not be null");
		checkNotNull(q, "Group Gq parameter q should not be null");
		checkNotNull(g, "Group Gq parameter g should not be null");

		final SecurityLevel securityLevel = SecurityLevelConfig.getSystemSecurityLevel();
		final String securityLevelCheckMessage = "The given p does not correspond to the given security level.";

		switch (securityLevel) {
		case EXTENDED:
			checkArgument(securityLevel.getBitLength() <= p.bitLength(), securityLevelCheckMessage);
			break;
		case DEFAULT:
			checkArgument(SecurityLevel.EXTENDED.getBitLength() > p.bitLength(), securityLevelCheckMessage);
			checkArgument(SecurityLevel.DEFAULT.getBitLength() <= p.bitLength(), securityLevelCheckMessage);
			break;
		case TESTING_ONLY:
			checkArgument(SecurityLevel.DEFAULT.getBitLength() > p.bitLength(), securityLevelCheckMessage);
			break;
		default:
			throw new IllegalArgumentException("Unsupported security level!");
		}

		//Validate p
		checkArgument(p.isProbablePrime(securityLevel.getStrength()), "Group Gq parameter p must be prime");
		this.p = p;

		//Validate q
		checkArgument(q.isProbablePrime(securityLevel.getStrength()), "Group Gq parameter q must be prime");
		checkArgument(q.compareTo(BigInteger.ZERO) > 0);
		checkArgument(q.compareTo(p) < 0);
		BigInteger computedP = q.multiply(BigInteger.valueOf(2)).add(BigInteger.ONE);
		checkArgument(computedP.equals(p), "Group Gq parameter p must be equal to 2q + 1");
		this.q = q;

		//Validate g
		checkArgument(g.compareTo(BigInteger.ONE) > 0);
		checkArgument(g.compareTo(p) < 0);
		checkArgument(isGroupMember(g), "Group Gq generator g %s must be a member of the group", g);
		generator = GqElementFactory.fromValue(g, this);

		identity = GqElementFactory.fromValue(BigInteger.ONE, this);
	}

	/**
	 * Checks if a value is a member of this group.
	 */
	@Override
	public boolean isGroupMember(final BigInteger value) {
		return isGroupMember(value, this.p);
	}

	/**
	 * Checks if a value is a member of a GqGroup defined by p.
	 */
	public static boolean isGroupMember(final BigInteger value, final BigInteger p) {
		return value != null &&
				value.compareTo(BigInteger.ZERO) > 0 &&
				value.compareTo(p) < 0 &&
				BigIntegerOperationsService.getJacobi(value, p) == 1;
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
	public boolean equals(final Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		final GqGroup gqGroup = (GqGroup) o;
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

	@Override
	public ImmutableList<? extends Hashable> toHashableForm() {
		return ImmutableList.of(HashableBigInteger.from(p), HashableBigInteger.from(q), generator);
	}
}
