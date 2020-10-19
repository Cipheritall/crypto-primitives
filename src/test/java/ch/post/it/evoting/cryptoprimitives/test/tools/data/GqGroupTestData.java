/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.test.tools.data;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.math.GqGroup;

public class GqGroupTestData {

	static ImmutableList<GqGroup> testGroups;

	static {
		//More groups can be added to this class as needed

		//First group
		final BigInteger p1 = new BigInteger("23");
		final BigInteger q1 = new BigInteger("11");
		final BigInteger g1 = new BigInteger("2");
		GqGroup group1 = new GqGroup(p1, q1, g1);

		//Second group
		final BigInteger p2 = new BigInteger("11");
		final BigInteger q2 = new BigInteger("5");
		final BigInteger g2 = new BigInteger("3");
		GqGroup group2 = new GqGroup(p2, q2, g2);

		testGroups = ImmutableList.of(group1, group2);
	}

	private GqGroupTestData() {
	}

	static public GqGroup getGroup() {
		return getRandomGroupFrom(testGroups);
	}

	static public GqGroup getDifferentGroup(final GqGroup group) {
		List<GqGroup> otherGroups = new ArrayList<>(testGroups);
		otherGroups.remove(group);
		return getRandomGroupFrom(otherGroups);
	}

	static private GqGroup getRandomGroupFrom(final List<GqGroup> groups) {
		SecureRandom random = new SecureRandom();
		return groups.get(random.nextInt(groups.size()));
	}
}
