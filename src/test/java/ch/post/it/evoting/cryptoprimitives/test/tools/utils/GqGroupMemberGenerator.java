/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.test.tools.utils;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;

/**
 * Brute force the generation of group members.
 */
public class GqGroupMemberGenerator {

	static final BigInteger MAX_GROUP_SIZE = BigInteger.valueOf(1000);
	private final GqGroup group;
	private final SecureRandom random;

	public GqGroupMemberGenerator(GqGroup group) {
		this.group = group;
		this.random = new SecureRandom();
	}

	public Set<BigInteger> getMembers() {
		if (group.getP().compareTo(MAX_GROUP_SIZE) > 0) {
			throw new IllegalArgumentException("It would take too much time to generate all the group members for such a large group.");
		}

		Set<BigInteger> members =
				pIntegers()
						.map(bi -> bi.modPow(BigInteger.valueOf(2), group.getP()))
						.collect(Collectors.toSet());
		members.remove(BigInteger.ZERO);
		return members;
	}

	public Set<BigInteger> getNonMembers() {
		if (group.getP().compareTo(MAX_GROUP_SIZE) > 0) {
			throw new IllegalArgumentException("It would take too much time to generate all the group members for such a large group.");
		}

		Set<BigInteger> members = getMembers();
		Set<BigInteger> nonMembers = pIntegers().collect(Collectors.toSet());
		nonMembers.removeAll(members);
		return nonMembers;
	}

	public BigInteger genMember() {
		BigInteger member;
		do {
			BigInteger randomInteger = randomBigInteger(group.getP().bitLength());
			member = randomInteger.modPow(BigInteger.valueOf(2), group.getP());
		} while (member.compareTo(BigInteger.ZERO) <= 0 || member.compareTo(group.getP()) >= 0);
		return member;
	}

	public GqElement genGqElementMember() {
		return GqElement.create(genMember(), group);
	}

	public BigInteger genNonMember() {
		BigInteger nonMember;
		do {
			nonMember = randomBigInteger(group.getP().bitLength());
		} while (nonMember.compareTo(BigInteger.ZERO) <= 0 || nonMember.compareTo(group.getP()) >= 0 || group.isGroupMember(nonMember));
		return nonMember;
	}

	public GqElement genNonIdentityGqElementMember() {
		GqElement nonIdentityMember;
		do {
			nonIdentityMember = genGqElementMember();
		} while (nonIdentityMember.equals(group.getIdentity()));
		return nonIdentityMember;
	}

	private BigInteger randomBigInteger(int bitLength) {
		return new BigInteger(bitLength, random);
	}

	private Stream<BigInteger> pIntegers() {
		return IntStream.range(1, group.getP().intValue()).mapToObj(BigInteger::valueOf);
	}
}
