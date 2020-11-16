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

class ZqGroupTest {

	private static ZqGroup testGroup;

	@BeforeAll
	static void setUp() {
		testGroup = new ZqGroup(BigInteger.TEN);
	}

	@Test
	void testCreateGroupWithNullThrows() {
		assertThrows(NullPointerException.class, () -> new ZqGroup(null));
	}

	@Test
	void testCanNotCreateAGroupWithQZero() {
		assertThrows(IllegalArgumentException.class, () -> new ZqGroup(BigInteger.ZERO));
	}

	@Test
	void testCanNotCreateAGroupWithQNegative() {
		BigInteger negativeQ = BigInteger.valueOf(-1);
		assertThrows(IllegalArgumentException.class, () -> new ZqGroup(negativeQ));
	}

	@Test
	void testNullIsNotGroupMember() {
		assertFalse(testGroup.isGroupMember(null));
	}

	@Test
	void testZeroIsGroupMember() {
		assertTrue(testGroup.isGroupMember(BigInteger.ZERO));
	}

	@Test
	void testQIsNotGroupMember() {
		assertFalse(testGroup.isGroupMember(testGroup.getQ()));
	}

	@Test
	void testOrderAndQAreTheSame() {
		assertEquals(testGroup.getQ(), testGroup.getQ());
	}

	@Test
	void testEquals() {
		ZqGroup same1 = new ZqGroup(BigInteger.TEN);
		ZqGroup same2 = new ZqGroup(BigInteger.TEN);
		ZqGroup differentQ = new ZqGroup(BigInteger.valueOf(20));

		assertEquals(same1, same2);
		assertNotEquals(same1, differentQ);
	}
}
