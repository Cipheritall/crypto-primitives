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
package ch.post.it.evoting.cryptoprimitives.test.tools.data;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.Generators;

/**
 * We only work with test groups where p is a safe prime, ie <code>p = 2 * q + 1</code> where p and q are prime.
 */
public class GroupTestData {

	private static final SecureRandom random = new SecureRandom();
	private static final ImmutableList<GqGroup> smallTestGroups;

	static {
		// More groups can be added to this class as needed.

		final BigInteger p1 = BigInteger.valueOf(11);
		final BigInteger q1 = BigInteger.valueOf(5);
		final BigInteger g1 = BigInteger.valueOf(3);
		final GqGroup group1 = new GqGroup(p1, q1, g1);

		final BigInteger p2 = BigInteger.valueOf(23);
		final BigInteger q2 = BigInteger.valueOf(11);
		final BigInteger g2 = BigInteger.valueOf(2);
		final GqGroup group2 = new GqGroup(p2, q2, g2);

		final BigInteger p3 = BigInteger.valueOf(47);
		final BigInteger q3 = BigInteger.valueOf(23);
		final BigInteger g3 = BigInteger.valueOf(2);
		final GqGroup group3 = new GqGroup(p3, q3, g3);

		final BigInteger p4 = BigInteger.valueOf(59);
		final BigInteger q4 = BigInteger.valueOf(29);
		final BigInteger g4 = BigInteger.valueOf(3);
		final GqGroup group4 = new GqGroup(p4, q4, g4);

		smallTestGroups = ImmutableList.of(group1, group2, group3, group4);
	}

	private GroupTestData() {
	}

	/**
	 * @return a random {@link GqGroup} from the predefined groups.
	 */
	public static GqGroup getGqGroup() {
		return getRandomGqGroupFrom(smallTestGroups);
	}

	/**
	 * Get a different group from the provided {@code gqGroup}.
	 *
	 * @param gqGroup the group for which to get a different one.
	 * @return a different {@link GqGroup}.
	 */
	public static GqGroup getDifferentGqGroup(final GqGroup gqGroup) {
		List<GqGroup> otherGroups = new ArrayList<>(smallTestGroups);
		otherGroups.remove(gqGroup);
		return getRandomGqGroupFrom(otherGroups);
	}

	/**
	 * @return a random {@link ZqGroup} from the predefined groups.
	 */
	public static ZqGroup getZqGroup() {
		return new ZqGroup(getGqGroup().getQ());
	}

	/**
	 * Get a different group from the provided {@code zqGroup}.
	 *
	 * @param zqGroup the group for which to get a different one.
	 * @return a different {@link ZqGroup}.
	 */
	public static ZqGroup getDifferentZqGroup(final ZqGroup zqGroup) {
		final BigInteger otherGqGroupQ = Generators.genWhile(() -> getGqGroup().getQ(), elem -> elem.equals(zqGroup.getQ()));

		return new ZqGroup(otherGqGroupQ);
	}

	/**
	 * Get the {@link GqGroup} defined in the "subgroup.json" file. As opposed to the groups defined in this class, this group is large with 2048 bits
	 * p and q.
	 *
	 * @return a {@link GqGroup}.
	 * @throws IOException if loading the group from the file fails.
	 */
	public static GqGroup getLargeGqGroup() throws IOException {
		return new GqGroupLoader("/subgroup.json").getGroup();
	}

	private static GqGroup getRandomGqGroupFrom(final List<GqGroup> groups) {
		return groups.get(random.nextInt(groups.size()));
	}

	public static GqGroup getGroupP59() {
		final BigInteger p = BigInteger.valueOf(59);
		final BigInteger q = BigInteger.valueOf(29);
		final BigInteger g = BigInteger.valueOf(3);
		return new GqGroup(p, q, g);
	}

}
