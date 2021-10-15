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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.SecurityLevel;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;

class GqGroupTest {
	private static final SecurityLevel SECURITY_LEVEL_CONFIG = SecurityLevel.TESTING_ONLY;

	private static BigInteger p;
	private static BigInteger q;
	private static BigInteger g;
	private static GqGroup smallGroup;
	private static GqGroupGenerator smallGroupGenerator;

	@BeforeAll
	static void setUp() {

		p = BigInteger.valueOf(23);
		q = BigInteger.valueOf(11);
		g = BigInteger.valueOf(2);
		smallGroup = new GqGroup(p, q, g);
		smallGroupGenerator = new GqGroupGenerator(smallGroup);
	}

	//Object instantiation validations

	@Test
	void testCreateGroupWithNonPrimePFails() {
		BigInteger nonPrime = BigInteger.valueOf(22);
		assertThrows(IllegalArgumentException.class, () -> new GqGroup(nonPrime, q, g));
	}

	@Test
	void testCreateGroupWithNonPrimeQFails() {
		BigInteger nonPrime = BigInteger.TEN;
		assertThrows(IllegalArgumentException.class, () -> new GqGroup(p, nonPrime, g));
	}

	@Test
	void testCreateGroupWithNonSafeQFails() {
		BigInteger nonSafePrimeQ = BigInteger.valueOf(7);
		assertThrows(IllegalArgumentException.class, () -> new GqGroup(p, nonSafePrimeQ, g));
	}

	@Test
	void testCreateGroupWithNonMemberGeneratorFails() {
		BigInteger nonMember = smallGroupGenerator.genNonMemberValue();
		assertThrows(IllegalArgumentException.class, () -> new GqGroup(p, q, nonMember));
	}

	//Methods

	@Test
	void testGroupMemberReturnsTrueForGroupMember() {
		BigInteger member = smallGroupGenerator.genMemberValue();
		assertTrue(smallGroup.isGroupMember(member));
	}

	@Test
	void testGroupMemberReturnsFalseForNonGroupMember() {
		BigInteger nonMember = smallGroupGenerator.genNonMemberValue();
		assertFalse(smallGroup.isGroupMember(nonMember));
	}

	@Test
	void test0IsNotAGroupMember() {
		assertFalse(smallGroup.isGroupMember(BigInteger.ZERO));
	}

	@Test
	void testPIsNotAGroupMember() {
		assertFalse(smallGroup.isGroupMember(smallGroup.getP()));
	}

	@Test
	void testNullIsNotAGroupMember() {
		assertFalse(smallGroup.isGroupMember(null));
	}

	@Test
	void testGetIdentityElementOnce() {
		GqElement identity = GqElement.create(BigInteger.ONE, smallGroup);
		assertEquals(identity, smallGroup.getIdentity(), "The element returned is not the expected identity element");
	}

	@Test
	void testGetIdentityElementTwice() {
		String errorMessage = "The %s element returned is not the expected identity element";
		GqElement identityElement = GqElement.create(BigInteger.ONE, smallGroup);
		GqElement firstIdentity = smallGroup.getIdentity();
		GqElement secondIdentity = smallGroup.getIdentity();

		assertEquals(identityElement, firstIdentity, String.format(errorMessage, "first"));
		assertEquals(identityElement, secondIdentity, String.format(errorMessage, "second"));
	}

	@Test
	void testGetQ() {
		assertEquals(q, smallGroup.getQ(), "The Q element is not the expected one");
	}

	@Test
	void testGetG() {
		assertEquals(g, smallGroup.getGenerator().getValue(), "The generator element is not the expected one");
	}

	@Test
	void testEqualsDifferentObjectType() {
		String notAGroup = "I am not a group";
		String errorMessage = "Expected that objects would not be equals";
		assertNotEquals(new GqGroup(p, q, g), notAGroup, errorMessage);
	}

	@Test
	void testEqualsTrue() {
		String errorMessage = "Expected that objects would be equals";
		assertEquals(new GqGroup(p, q, g), smallGroup, errorMessage);
	}

	@Test
	void testIsPrimeTrue() {
		assertTrue(GqGroup.isPrime(2));
		assertTrue(GqGroup.isPrime(3));
		assertTrue(GqGroup.isPrime(5));
		assertTrue(GqGroup.isPrime(7));
		assertTrue(GqGroup.isPrime(11));
		assertTrue(GqGroup.isPrime(47));
	}

	@Test
	void testIsPrimeFalse() {
		assertFalse(GqGroup.isPrime(1));
		assertFalse(GqGroup.isPrime(4));
		assertFalse(GqGroup.isPrime(9));
		assertFalse(GqGroup.isPrime(35));
		assertFalse(GqGroup.isPrime(77));
		assertFalse(GqGroup.isPrime(143));
	}

	@Test
	void testIsPrimeTooSmallNThrows() {
		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> GqGroup.isPrime(0));
		assertEquals("The number n must be strictly positive", exception.getMessage());
	}

	@Test
	void testGetSmallGroupMembersOk() {
		final GqGroup gqGroup = new GqGroup(BigInteger.valueOf(47), BigInteger.valueOf(23), BigInteger.valueOf(2));
		final GroupVector<GqElement, GqGroup> primes = gqGroup.getSmallPrimeGroupMembers(3);
		assertEquals(3, primes.size());
		assertEquals(BigInteger.valueOf(7), primes.get(0).getValue());
		assertEquals(BigInteger.valueOf(17), primes.get(1).getValue());
		assertEquals(BigInteger.valueOf(37), primes.get(2).getValue());
	}

	@Test
	void testGetSmallGroupMembersTooSmallRThrows() {
		final GqGroup gqGroup = new GqGroup(BigInteger.valueOf(47), BigInteger.valueOf(23), BigInteger.valueOf(2));
		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> gqGroup.getSmallPrimeGroupMembers(0));
		assertEquals("The desired number of primes must be strictly positive", exception.getMessage());
	}

	@Test
	void testGetSmallGroupMembersTooBigRThrows() {
		final GqGroup gqGroup = new GqGroup(BigInteger.valueOf(47), BigInteger.valueOf(23), BigInteger.valueOf(2));
		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> gqGroup.getSmallPrimeGroupMembers(23));
		assertEquals("The number of desired primes must be smaller than the number of elements in the GqGroup by at least 4", exception.getMessage());

		final GqGroup bigGqGroup = new GqGroup(BigInteger.valueOf(20123), BigInteger.valueOf(10061), BigInteger.valueOf(3));
		exception = assertThrows(IllegalArgumentException.class,
				() -> bigGqGroup.getSmallPrimeGroupMembers(10000));
		assertEquals("The number of desired primes must be smaller than 10000", exception.getMessage());
	}

	@Test
	void testGetSmallGroupMembersNotEnoughPrimesThrows() {
		final GqGroup gqGroup = new GqGroup(BigInteger.valueOf(47), BigInteger.valueOf(23), BigInteger.valueOf(2));
		IllegalStateException exception = assertThrows(IllegalStateException.class,
				() -> gqGroup.getSmallPrimeGroupMembers(4));
		assertEquals("The number of primes found does not correspond to the number of desired primes.", exception.getMessage());
	}
}
