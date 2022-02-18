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
		final BigInteger negativeQ = BigInteger.valueOf(-1);
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
		final ZqGroup same1 = new ZqGroup(BigInteger.TEN);
		final ZqGroup same2 = new ZqGroup(BigInteger.TEN);
		final ZqGroup differentQ = new ZqGroup(BigInteger.valueOf(20));

		assertEquals(same1, same2);
		assertNotEquals(same1, differentQ);
	}
}
