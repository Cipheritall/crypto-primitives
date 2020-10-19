/*
 * HEADER_LICENSE_OPEN_SOURCE
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

import ch.post.it.evoting.cryptoprimitives.test.tools.utils.GqGroupMemberGenerator;

class GqGroupTest {
	private static BigInteger p;
	private static BigInteger q;
	private static BigInteger g;
	private static GqGroup smallGroup;
	private static GqGroupMemberGenerator smallGroupGenerator;

	@BeforeAll
	static void setUp() {

		p = new BigInteger("23");
		q = new BigInteger("11");
		g = new BigInteger("2");
		smallGroup = new GqGroup(p, q, g);
		smallGroupGenerator = new GqGroupMemberGenerator(smallGroup);
	}

	//Object instantiation validations

	@Test
	void testCreateGroupWithNonPrimePFails() {
		BigInteger nonPrime = BigInteger.valueOf(22);
		assertThrows(IllegalArgumentException.class, () -> new GqGroup(nonPrime, q, g));
	}

	@Test
	void testCreateGroupWithNonPrimeQFails() {
		BigInteger nonPrime = BigInteger.valueOf(10);
		assertThrows(IllegalArgumentException.class, () -> new GqGroup(p, nonPrime, g));
	}

	@Test
	void testCreateGroupWithNonSafeQFails() {
		BigInteger nonSafePrimeQ = BigInteger.valueOf(7);
		assertThrows(IllegalArgumentException.class, () -> new GqGroup(p, nonSafePrimeQ, g));
	}

	@Test
	void testCreateGroupWithNonMemberGeneratorFails() {
		BigInteger nonMember = smallGroupGenerator.genNonMember();
		assertThrows(IllegalArgumentException.class, () -> new GqGroup(p, q, nonMember));
	}

	//Methods

	@Test
	void testGroupMemberReturnsTrueForGroupMember() {
		BigInteger member = smallGroupGenerator.genMember();
		assertTrue(smallGroup.isGroupMember(member));
	}

	@Test
	void testGroupMemberReturnsFalseForNonGroupMember() {
		BigInteger nonMember = smallGroupGenerator.genNonMember();
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
}
