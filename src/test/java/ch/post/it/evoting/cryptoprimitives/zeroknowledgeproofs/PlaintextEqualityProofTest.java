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
package ch.post.it.evoting.cryptoprimitives.zeroknowledgeproofs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.TestGroupSetup;

@DisplayName("A PlaintextEqualityProof")
class PlaintextEqualityProofTest extends TestGroupSetup {

	private ZqElement e;
	private GroupVector<ZqElement, ZqGroup> z;

	@BeforeEach
	void setUp() {
		e = zqGroupGenerator.genRandomZqElementMember();
		z = zqGroupGenerator.genRandomZqElementVector(2);
	}

	@Test
	@DisplayName("equals works as expected")
	void equalsTest() {
		final PlaintextEqualityProof proof1 = new PlaintextEqualityProof(e, z);
		final GroupVector<ZqElement, ZqGroup> z2 = zqGroupGenerator.genRandomZqElementVector(2);
		final PlaintextEqualityProof proof2 = new PlaintextEqualityProof(e, z2);
		final ZqElement e3 = zqGroupGenerator.otherElement(e);
		final PlaintextEqualityProof proof3 = new PlaintextEqualityProof(e3, z);
		final PlaintextEqualityProof proof4 = new PlaintextEqualityProof(e, z);

		assertNotEquals(null, proof1);
		assertEquals(proof1, proof1);
		assertNotEquals(proof1, proof2);
		assertNotEquals(proof1, proof3);
		assertEquals(proof1, proof4);
	}

	@Nested
	@DisplayName("constructed with")
	class Constructor {

		@Test
		@DisplayName("valid parameters gives valid proof")
		void validParams() {
			final PlaintextEqualityProof plaintextEqualityProof = new PlaintextEqualityProof(e, z);

			assertEquals(plaintextEqualityProof.get_e().getGroup(), plaintextEqualityProof.get_z().getGroup());
			assertEquals(2, plaintextEqualityProof.get_z().size());
		}

		@Test
		@DisplayName("any null parameter throws NullPointerException")
		void nullParams() {
			assertThrows(NullPointerException.class, () -> new PlaintextEqualityProof(null, z));
			assertThrows(NullPointerException.class, () -> new PlaintextEqualityProof(e, null));
		}

		@Test
		@DisplayName("z not having exactly two elements throws IllegalArgumentException")
		void wrongSizeZ() {
			final GroupVector<ZqElement, ZqGroup> shortZ = zqGroupGenerator.genRandomZqElementVector(1);
			final IllegalArgumentException shortException = assertThrows(IllegalArgumentException.class, () -> new PlaintextEqualityProof(e, shortZ));
			assertEquals("z must have exactly two elements.", shortException.getMessage());

			final GroupVector<ZqElement, ZqGroup> longZ = zqGroupGenerator.genRandomZqElementVector(3);
			final IllegalArgumentException longException = assertThrows(IllegalArgumentException.class, () -> new PlaintextEqualityProof(e, longZ));
			assertEquals("z must have exactly two elements.", longException.getMessage());
		}

		@Test
		@DisplayName("e and z from different groups throws IllegalArgumentException")
		void differentGroupEAndZ() {
			final ZqElement otherGroupE = otherZqGroupGenerator.genRandomZqElementMember();

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> new PlaintextEqualityProof(otherGroupE, z));
			assertEquals("e and z must be from the same group.", exception.getMessage());
		}

	}

}
