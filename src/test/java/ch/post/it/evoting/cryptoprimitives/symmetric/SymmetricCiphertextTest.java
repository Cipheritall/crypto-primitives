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
package ch.post.it.evoting.cryptoprimitives.symmetric;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.Test;

class SymmetricCiphertextTest {

	@Test
	void checkConstructionImmutability() {
		final byte[] sourceCiphertext = new byte[] { 1, 2, 3 };
		final byte[] sourceNonce = new byte[] { 4, 5, 6 };
		final SymmetricCiphertext symmetricCiphertext = new SymmetricCiphertext(sourceCiphertext, sourceNonce);

		// Mute source arrays
		sourceCiphertext[0] = 7;
		sourceNonce[0] = 8;

		// SymmetricCiphertext inner values must be not equal to source
		assertNotEquals(sourceCiphertext[0], symmetricCiphertext.getCiphertext()[0]);
		assertEquals(1, symmetricCiphertext.getCiphertext()[0]);
		assertNotEquals(sourceNonce[0], symmetricCiphertext.getNonce()[0]);
		assertEquals(4, symmetricCiphertext.getNonce()[0]);
	}

	@Test
	void checkGettersImmutability() {
		final SymmetricCiphertext symmetricCiphertext = new SymmetricCiphertext(new byte[] { 1, 2, 3 }, new byte[] { 4, 5, 6 });
		final byte[] ciphertext = symmetricCiphertext.getCiphertext();
		final byte[] nonce = symmetricCiphertext.getNonce();

		// Mute arrays from getter
		ciphertext[0] = 7;
		nonce[0] = 8;

		// SymmetricCiphertext inner values must be not equal to muted
		assertNotEquals(ciphertext[0], symmetricCiphertext.getCiphertext()[0]);
		assertEquals(1, symmetricCiphertext.getCiphertext()[0]);
		assertNotEquals(nonce[0], symmetricCiphertext.getNonce()[0]);
		assertEquals(4, symmetricCiphertext.getNonce()[0]);
	}
}