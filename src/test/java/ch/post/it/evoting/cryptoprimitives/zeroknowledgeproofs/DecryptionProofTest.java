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

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.SecureRandom;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.TestGroupSetup;

class DecryptionProofTest extends TestGroupSetup {

	private static final SecureRandom secureRandom = new SecureRandom();

	private int l;
	private ZqElement e;
	private GroupVector<ZqElement, ZqGroup> z;

	@BeforeEach
	void setup() {
		l = secureRandom.nextInt(10) + 1;
		e = zqGroupGenerator.genRandomZqElementMember();
		z = zqGroupGenerator.genRandomZqElementVector(l);
	}

	@Test
	@DisplayName("Constructing a DecryptionProof with null arguments throws a NullPointerException")
	void constructDecryptionProofWithNullArguments() {
		assertAll(
				() -> assertThrows(NullPointerException.class, () -> new DecryptionProof(null, z)),
				() -> assertThrows(NullPointerException.class, () -> new DecryptionProof(e, null))
		);
	}

	@Test
	@DisplayName("Constructing a DecryptionProof with e and z from different groups throws an IllegalArgumentException")
	void constructDecryptionProofWithEAndZDifferentGroups() {
		GroupVector<ZqElement, ZqGroup> z = otherZqGroupGenerator.genRandomZqElementVector(l);
		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> new DecryptionProof(e, z));
		assertEquals("e and z must have the same group.", exception.getMessage());
	}

	@Test
	@DisplayName("Constructing a DecryptionProof with valid parameters does not throw")
	void constructDecryptionProofWithValidParameters() {
		assertDoesNotThrow(() -> new DecryptionProof(e, z));
	}

	@Test
	void equalsTest() {
		DecryptionProof proof1 = new DecryptionProof(e, z);
		GroupVector<ZqElement, ZqGroup> z2 = zqGroupGenerator.genRandomZqElementVector(l + 1);
		DecryptionProof proof2 = new DecryptionProof(e, z2);
		ZqElement e3 = zqGroupGenerator.genOtherElement(e);
		DecryptionProof proof3 = new DecryptionProof(e3, z);
		DecryptionProof proof4 = new DecryptionProof(e, z);

		assertNotEquals(null, proof1);
		assertEquals(proof1, proof1);
		assertNotEquals(proof1, proof2);
		assertNotEquals(proof1, proof3);
		assertEquals(proof1, proof4);
	}
}
