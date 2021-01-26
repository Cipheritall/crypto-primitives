/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.test.tools.generator;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Set;
import java.util.function.Predicate;
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

	/**
	 * Get all members of the group.
	 */
	public Set<BigInteger> getMembers() {
		if (group.getP().compareTo(MAX_GROUP_SIZE) > 0) {
			throw new IllegalArgumentException("It would take too much time to generate all the group members for such a large group.");
		}

		Set<BigInteger> members =
				integersModP()
						.map(bi -> bi.modPow(BigInteger.valueOf(2), group.getP()))
						.collect(Collectors.toSet());
		members.remove(BigInteger.ZERO);
		return members;
	}

	/**
	 * Get all non members of the group smaller than p.
	 */
	public Set<BigInteger> getNonMembers() {
		if (group.getP().compareTo(MAX_GROUP_SIZE) > 0) {
			throw new IllegalArgumentException("It would take too much time to generate all the group members for such a large group.");
		}

		Set<BigInteger> members = getMembers();
		Set<BigInteger> nonMembers = integersModP().collect(Collectors.toSet());
		nonMembers.removeAll(members);
		return nonMembers;
	}

	/**
	 * Generate a BigInteger value that belongs to the group.
	 */
	public BigInteger genMemberValue() {
		BigInteger member;
		do {
			BigInteger randomInteger = randomBigInteger(group.getP().bitLength());
			member = randomInteger.modPow(BigInteger.valueOf(2), group.getP());
		} while (member.compareTo(BigInteger.ZERO) <= 0 || member.compareTo(group.getP()) >= 0);
		return member;
	}

	/**
	 * Generate a GqElement belonging to the group.
	 */
	public GqElement genMember() {
		return GqElement.create(genMemberValue(), group);
	}

	/**
	 * Generate a BigInteger value that does not belong to the group.
	 */
	public BigInteger genNonMemberValue() {
		BigInteger nonMember;
		do {
			nonMember = randomBigInteger(group.getP().bitLength());
		} while (nonMember.compareTo(BigInteger.ZERO) <= 0 || nonMember.compareTo(group.getP()) >= 0 || group.isGroupMember(nonMember));
		return nonMember;
	}

	/**
	 * Generate a non identity member of the group.
	 */
	public GqElement genNonIdentityMember() {
		return genMember(member -> member.equals(group.getIdentity()));
	}

	/**
	 * Generate a non identity, non generator member of the group.
	 */
	public GqElement genNonIdentityNonGeneratorMember() {
		return genMember(member -> member.equals(group.getIdentity()) || member.equals(group.getGenerator()));
	}

	private GqElement genMember(Predicate<GqElement> invalid) {
		GqElement member;
		do {
			member = genMember();
		} while (invalid.test(member));
		return member;
	}


	private BigInteger randomBigInteger(int bitLength) {
		return new BigInteger(bitLength, random);
	}

	private Stream<BigInteger> integersModP() {
		return IntStream.range(1, group.getP().intValue()).mapToObj(BigInteger::valueOf);
	}
}