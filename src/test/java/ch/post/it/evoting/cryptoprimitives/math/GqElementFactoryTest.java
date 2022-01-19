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

import static ch.post.it.evoting.cryptoprimitives.math.GqElement.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;

class GqElementFactoryTest {

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
	void givenAValueWhenAGroupElementIsCreatedWithThatValueThenHasThatValue() {
		BigInteger value = BigInteger.valueOf(2);
		GqElement element = GqElementFactory.fromValue(value, group);
		assertEquals(value, element.getValue(), "The returned element value is not the expected one");
	}

	@Test
	void whenCreateAnElementWithValueZeroThenError() {
		BigInteger value = BigInteger.ZERO;
		assertThrows(IllegalArgumentException.class, () -> GqElementFactory.fromValue(value, group));
	}

	@Test
	void whenCreateAnElementWithNegativeValueThenError() {
		BigInteger value = BigInteger.valueOf(-1);
		assertThrows(IllegalArgumentException.class, () -> GqElementFactory.fromValue(value, group));
	}

	@Test
	void whenCreateAnElementWithValueGreaterThanPThenError() {
		BigInteger value = BigInteger.valueOf(24);
		assertThrows(IllegalArgumentException.class, () -> GqElementFactory.fromValue(value, group));
	}

	@Test
	void whenCreateAnElementWithNullValueThenError() {
		assertThrows(NullPointerException.class, () -> GqElementFactory.fromValue(null, group));
	}

	@Test
	void whenCreateAnElementWithNullGroupThenError() {
		BigInteger value = BigInteger.ONE;
		assertThrows(NullPointerException.class, () -> GqElementFactory.fromValue(value, null));
	}

	@Test
	void whenCreateAnElementNotMemberOfTheGroupError() {
		BigInteger nonMemberValue = groupGenerator.genNonMemberValue();
		assertThrows(IllegalArgumentException.class, () -> GqElementFactory.fromValue(nonMemberValue, group));
	}

	@Test
	void whenCreateAnElementMemberOfTheGroupNoError() {
		BigInteger memberValue = groupGenerator.genMemberValue();
		GqElement groupMember = GqElementFactory.fromValue(memberValue, group);
		assertTrue(group.isGroupMember(groupMember.getValue()));
	}

	@Test
	void testFromSquareRootWithNullArgumentsThrows() {
		assertThrows(NullPointerException.class, () -> GqElementFactory.fromSquareRoot(null, group));
		assertThrows(NullPointerException.class, () -> GqElementFactory.fromSquareRoot(BigInteger.ONE, null));
	}

	@Test
	void testFromSquareRootWithZeroThrows() {
		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> GqElementFactory.fromSquareRoot(BigInteger.ZERO, group));
		assertEquals("The element must be strictly greater than 0", exception.getMessage());
	}

	@Test
	void testFromSquareRootWithTooBigElementThrows() {
		final BigInteger element = group.getQ();
		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> GqElementFactory.fromSquareRoot(element, group));
		assertEquals("The element must be smaller than the group's order", exception.getMessage());
	}

	@Test
	void testFromSquareRootWithValidInputReturnsSquaredElement() {
		final ZqGroup zqGroup = ZqGroup.sameOrderAs(group);
		final BigInteger one = BigInteger.ONE;
		final BigInteger two = BigInteger.valueOf(2);
		final BigInteger five = BigInteger.valueOf(5);

		final GqElement resultOne = GqElementFactory.fromValue(BigInteger.ONE, group);
		final GqElement resultFour = GqElementFactory.fromValue(BigInteger.valueOf(4), group);
		final GqElement resultTwo = GqElementFactory.fromValue(BigInteger.valueOf(2), group);

		assertEquals(GqElementFactory.fromSquareRoot(one, group), resultOne);
		assertEquals(GqElementFactory.fromSquareRoot(two, group), resultFour);
		assertEquals(GqElementFactory.fromSquareRoot(five, group), resultTwo);
	}

	@Test
	void testIsPrimeTrue() {
		assertTrue(GqElementFactory.isPrime(2));
		assertTrue(GqElementFactory.isPrime(3));
		assertTrue(GqElementFactory.isPrime(5));
		assertTrue(GqElementFactory.isPrime(7));
		assertTrue(GqElementFactory.isPrime(11));
		assertTrue(GqElementFactory.isPrime(47));
	}

	@Test
	void testIsPrimeFalse() {
		assertFalse(GqElementFactory.isPrime(1));
		assertFalse(GqElementFactory.isPrime(4));
		assertFalse(GqElementFactory.isPrime(9));
		assertFalse(GqElementFactory.isPrime(35));
		assertFalse(GqElementFactory.isPrime(77));
		assertFalse(GqElementFactory.isPrime(143));
	}

	@Test
	void testIsPrimeTooSmallNThrows() {
		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> GqElementFactory.isPrime(0));
		assertEquals("The number n must be strictly positive", exception.getMessage());
	}

	@Test
	void testGetSmallGroupMembersOk() {
		final GqGroup gqGroup = new GqGroup(BigInteger.valueOf(47), BigInteger.valueOf(23), BigInteger.valueOf(2));
		final GroupVector<GqElement, GqGroup> primes = GqElementFactory.getSmallPrimeGroupMembers(gqGroup, 3);
		assertEquals(3, primes.size());
		assertEquals(BigInteger.valueOf(7), primes.get(0).getValue());
		assertEquals(BigInteger.valueOf(17), primes.get(1).getValue());
		assertEquals(BigInteger.valueOf(37), primes.get(2).getValue());
	}

	@Test
	void testGetSmallGroupMembersTooSmallRThrows() {
		final GqGroup gqGroup = new GqGroup(BigInteger.valueOf(47), BigInteger.valueOf(23), BigInteger.valueOf(2));
		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> GqElementFactory.getSmallPrimeGroupMembers(gqGroup, 0));
		assertEquals("The desired number of primes must be strictly positive", exception.getMessage());
	}

	@Test
	void testGetSmallGroupMembersTooBigRThrows() {
		final GqGroup gqGroup = new GqGroup(BigInteger.valueOf(47), BigInteger.valueOf(23), BigInteger.valueOf(2));
		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> GqElementFactory.getSmallPrimeGroupMembers(gqGroup, 23));
		assertEquals("The number of desired primes must be smaller than the number of elements in the GqGroup by at least 4", exception.getMessage());

		final GqGroup bigGqGroup = new GqGroup(BigInteger.valueOf(20123), BigInteger.valueOf(10061), BigInteger.valueOf(3));
		exception = assertThrows(IllegalArgumentException.class,
				() -> GqElementFactory.getSmallPrimeGroupMembers(bigGqGroup, 10000));
		assertEquals("The number of desired primes must be smaller than 10000", exception.getMessage());
	}

	@Test
	void testGetSmallGroupMembersNotEnoughPrimesThrows() {
		final GqGroup gqGroup = new GqGroup(BigInteger.valueOf(47), BigInteger.valueOf(23), BigInteger.valueOf(2));
		IllegalStateException exception = assertThrows(IllegalStateException.class,
				() -> GqElementFactory.getSmallPrimeGroupMembers(gqGroup, 4));
		assertEquals("The number of primes found does not correspond to the number of desired primes.", exception.getMessage());
	}
}
