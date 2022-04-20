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
package ch.post.it.evoting.cryptoprimitives.zeroknowledgeproofs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.test.tools.TestGroupSetup;

@DisplayName("A SchnorrProof")
class SchnorrProofTest extends TestGroupSetup {

	private ZqElement e;
	private ZqElement z;

	@BeforeEach
	void setUp() {
		e = zqGroupGenerator.genRandomZqElementMember();
		z = zqGroupGenerator.genRandomZqElementMember();
	}

	@Test
	@DisplayName("equals works as expected")
	void equalsTest() {
		final SchnorrProof proof1 = new SchnorrProof(e, z);
		final ZqElement z2 = zqGroupGenerator.genOtherElement(z);
		final SchnorrProof proof2 = new SchnorrProof(e, z2);
		final ZqElement e3 = zqGroupGenerator.genOtherElement(e);
		final SchnorrProof proof3 = new SchnorrProof(e3, z);
		final SchnorrProof proof4 = new SchnorrProof(e, z);

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
			final SchnorrProof schnorrProof = new SchnorrProof(e, z);

			assertEquals(schnorrProof.get_e().getGroup(), schnorrProof.get_z().getGroup());
			assertEquals(1, schnorrProof.get_z().size());
		}

		@Test
		@DisplayName("any null parameter throws NullPointerException")
		void nullParams() {
			assertThrows(NullPointerException.class, () -> new SchnorrProof(null, z));
			assertThrows(NullPointerException.class, () -> new SchnorrProof(e, null));
		}

		@Test
		@DisplayName("e and z from different groups throws IllegalArgumentException")
		void differentGroupEAndZ() {
			final ZqElement otherGroupE = otherZqGroupGenerator.genRandomZqElementMember();

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> new SchnorrProof(otherGroupE, z));
			assertEquals("e and z must be from the same group.", exception.getMessage());
		}
	}
}
