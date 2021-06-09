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

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;

class ExponentiationProofTest extends TestGroupSetup {

	private ZqElement e;
	private ZqElement z;

	@BeforeEach
	void setup() {
		e = zqGroupGenerator.genRandomZqElementMember();
		z = zqGroupGenerator.genRandomZqElementMember();
	}

	@Test
	void notNullCheck() {
		assertThrows(NullPointerException.class, () -> new ExponentiationProof(e, null));
		assertThrows(NullPointerException.class, () -> new ExponentiationProof(null, z));
	}

	@Test
	void sameGroupCheck() {
		final ZqElement otherZ = otherZqGroupGenerator.genRandomZqElementMember();
		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> new ExponentiationProof(e, otherZ));
		assertEquals("e and z must be from the same group.", exception.getMessage());
	}

	@Test
	void validArtguments() {
		assertDoesNotThrow(() -> new ExponentiationProof(e, z));
	}
}