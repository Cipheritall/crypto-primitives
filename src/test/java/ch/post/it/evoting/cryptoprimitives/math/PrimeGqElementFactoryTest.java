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
package ch.post.it.evoting.cryptoprimitives.math;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;

class PrimeGqElementFactoryTest {

	private static GqGroup group;
	private static GqGroupGenerator groupGenerator;

	@BeforeAll
	static void setUp() {
		final BigInteger p = BigInteger.valueOf(23);
		final BigInteger q = BigInteger.valueOf(11);
		final BigInteger g = BigInteger.valueOf(2);

		group = new GqGroup(p, q, g);
		groupGenerator = new GqGroupGenerator(group);
	}

	@Test
	void givenAValueWhenAPrimeGroupElementIsCreatedWithThatValueThenHasThatValue() {
		final int value = 3;
		final PrimeGqElement element = PrimeGqElement.PrimeGqElementFactory.fromValue(value, group);
		assertEquals(value, element.getValue().intValueExact(), "The returned element value is not the expected one");
	}

	@ParameterizedTest(name = "[{index}] - with value {0}")
	@ValueSource(ints = { 0, -1, 4, 27 })
	void whenCreateAPrimeElementWithInvalidValueThenError(final int value) {
		assertThrows(IllegalArgumentException.class, () -> PrimeGqElement.PrimeGqElementFactory.fromValue(value, group));
	}

	@Test
	void whenCreateAPrimeElementWithNullGroupThenError() {
		final int value = 7;
		assertThrows(NullPointerException.class, () -> PrimeGqElement.PrimeGqElementFactory.fromValue(value, null));
	}

	@Test
	void whenCreateAPrimeElementEqualToGroupGeneratorError() {
		final int groupGenerator = group.getGenerator().value.intValueExact();
		assertThrows(IllegalArgumentException.class, () -> PrimeGqElement.PrimeGqElementFactory.fromValue(groupGenerator, group));
	}

	@Test
	void whenCreateAPrimeElementNotMemberOfTheGroupError() {
		final int nonMemberValue = groupGenerator.genNonMemberValue().intValueExact();
		assertThrows(IllegalArgumentException.class, () -> PrimeGqElement.PrimeGqElementFactory.fromValue(nonMemberValue, group));
	}

	@Test
	void whenCreateAPrimeElementPrimeMemberOfTheGroupNoError() {
		final int memberValue = 13;
		final PrimeGqElement groupMember = PrimeGqElement.PrimeGqElementFactory.fromValue(memberValue, group);
		assertTrue(group.isGroupMember(groupMember.getValue()));
	}

	@Test
	void testGetSmallGroupMembersOk() {
		final GqGroup gqGroup = new GqGroup(BigInteger.valueOf(47), BigInteger.valueOf(23), BigInteger.valueOf(2));
		final GroupVector<PrimeGqElement, GqGroup> primes = PrimeGqElement.PrimeGqElementFactory.getSmallPrimeGroupMembers(gqGroup, 3);
		assertEquals(3, primes.size());
		assertEquals(BigInteger.valueOf(7), primes.get(0).getValue());
		assertEquals(BigInteger.valueOf(17), primes.get(1).getValue());
		assertEquals(BigInteger.valueOf(37), primes.get(2).getValue());
	}

	@Test
	void testGetSmallGroupMembersTooSmallRThrows() {
		final GqGroup gqGroup = new GqGroup(BigInteger.valueOf(47), BigInteger.valueOf(23), BigInteger.valueOf(2));
		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> PrimeGqElement.PrimeGqElementFactory.getSmallPrimeGroupMembers(gqGroup, 0));
		assertEquals("The desired number of primes must be strictly positive", exception.getMessage());
	}

	@Test
	void testGetSmallGroupMembersTooBigRThrows() {
		final GqGroup gqGroup = new GqGroup(BigInteger.valueOf(47), BigInteger.valueOf(23), BigInteger.valueOf(2));
		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> PrimeGqElement.PrimeGqElementFactory.getSmallPrimeGroupMembers(gqGroup, 23));
		assertEquals("The desired number of primes must be smaller than the number of elements in the GqGroup by at least 4", exception.getMessage());

		final GqGroup bigGqGroup = new GqGroup(BigInteger.valueOf(20123), BigInteger.valueOf(10061), BigInteger.valueOf(3));
		exception = assertThrows(IllegalArgumentException.class,
				() -> PrimeGqElement.PrimeGqElementFactory.getSmallPrimeGroupMembers(bigGqGroup, 10000));
		assertEquals("The desired number of primes must be strictly smaller than 10000", exception.getMessage());
	}

	@Test
	void testGetSmallGroupMembersNotEnoughPrimesThrows() {
		final GqGroup gqGroup = new GqGroup(BigInteger.valueOf(47), BigInteger.valueOf(23), BigInteger.valueOf(2));
		final IllegalStateException exception = assertThrows(IllegalStateException.class,
				() -> PrimeGqElement.PrimeGqElementFactory.getSmallPrimeGroupMembers(gqGroup, 4));
		assertEquals("The number of primes found does not correspond to the number of desired primes.", exception.getMessage());
	}
}
