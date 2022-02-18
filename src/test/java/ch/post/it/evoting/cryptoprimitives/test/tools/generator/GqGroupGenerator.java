/*
 * Copyright 2022 Post CH Ltd
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
package ch.post.it.evoting.cryptoprimitives.test.tools.generator;

import static ch.post.it.evoting.cryptoprimitives.math.GqElement.GqElementFactory;
import static ch.post.it.evoting.cryptoprimitives.test.tools.generator.GroupVectorElementGenerator.generateElementList;
import static ch.post.it.evoting.cryptoprimitives.test.tools.generator.GroupVectorElementGenerator.generateElementMatrix;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupMatrix;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;

/**
 * Brute force the generation of group members.
 */
public class GqGroupGenerator {

	private static final BigInteger MAX_GROUP_SIZE = BigInteger.valueOf(1000);

	private final GqGroup group;
	private final SecureRandom random;

	public GqGroupGenerator(final GqGroup group) {
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

		final Set<BigInteger> members =
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

		final Set<BigInteger> members = getMembers();
		final Set<BigInteger> nonMembers = integersModP().collect(Collectors.toSet());
		nonMembers.removeAll(members);
		return nonMembers;
	}

	/**
	 * Generate a BigInteger value that belongs to the group.
	 */
	public BigInteger genMemberValue() {
		BigInteger member;
		do {
			final BigInteger randomInteger = randomBigInteger(group.getP().bitLength());
			member = randomInteger.modPow(BigInteger.valueOf(2), group.getP());
		} while (member.compareTo(BigInteger.ZERO) <= 0 || member.compareTo(group.getP()) >= 0);
		return member;
	}

	/**
	 * Generate a GqElement belonging to the group.
	 */
	public GqElement genMember() {
		return GqElementFactory.fromValue(genMemberValue(), group);
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
		return Generators.genWhile(this::genMember, member -> member.equals(group.getIdentity()));
	}

	/**
	 * Generate a non identity, non generator member of the group.
	 */
	public GqElement genNonIdentityNonGeneratorMember() {
		return Generators.genWhile(this::genMember, member -> member.equals(group.getIdentity()) || member.equals(group.getGenerator()));
	}

	/**
	 * Generate a random {@link GroupVector} of {@link GqElement} in this {@code group}.
	 *
	 * @param numElements the number of elements to generate.
	 * @return a vector of {@code numElements} random {@link GqElement}.
	 */
	public GroupVector<GqElement, GqGroup> genRandomGqElementVector(final int numElements) {
		return GroupVector.from(generateElementList(numElements, this::genMember));
	}

	public GroupMatrix<GqElement, GqGroup> genRandomGqElementMatrix(final int numRows, final int numColumns) {
		final List<List<GqElement>> elements = generateElementMatrix(numRows, numColumns, this::genMember);
		return GroupMatrix.fromRows(elements);
	}

	private BigInteger randomBigInteger(final int bitLength) {
		return new BigInteger(bitLength, random);
	}

	private Stream<BigInteger> integersModP() {
		return IntStream.range(1, group.getP().intValue()).mapToObj(BigInteger::valueOf);
	}

	public GqElement otherElement(final GqElement element) {
		return Generators.genWhile(this::genMember, element::equals);
	}
}
