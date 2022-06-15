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
package ch.post.it.evoting.cryptoprimitives.elgamal;

import ch.post.it.evoting.cryptoprimitives.internal.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.Random;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;

public interface ElGamal {

	/**
	 * Encrypts a message with the given public key and provided randomness.
	 * <p>
	 * The {@code message}, {@code exponent} and {@code publicKey} parameters must comply with the following:
	 * <ul>
	 *     <li>the message size must be at most the public key size.</li>
	 *     <li>the message and the public key groups must be the same.</li>
	 *     <li>the message and the exponent must belong to groups of same order.</li>
	 * </ul>
	 *
	 * @param message   m, the plaintext message. Must be non null and not empty.
	 * @param exponent  r, a random exponent. Must be non null.
	 * @param publicKey pk, the public key to use to encrypt the message. Must be non null.
	 * @return A ciphertext containing the encrypted message.
	 */
	ElGamalMultiRecipientCiphertext getCiphertext(final ElGamalMultiRecipientMessage message, final ZqElement exponent,
			final ElGamalMultiRecipientPublicKey publicKey);

	/**
	 * Creates a neutral element for ciphertext multiplication.
	 * <p>
	 * The neutral element for ciphertext multiplication is (γ, 𝜙₀,..., 𝜙ₗ₋₁) = (1, 1, ..., 1).
	 *
	 * @param numPhi The number of phis in the neutral element.
	 * @param group  The {@link GqGroup} of the neutral element.
	 * @return A new {@link ElGamalMultiRecipientCiphertext} filled with ones.
	 */
	ElGamalMultiRecipientCiphertext neutralElement(final int numPhi, final GqGroup group);


		/**
		 * Decrypts a ciphertext to obtain the plaintext message.
		 * <p>
		 * The {@code ciphertext} and {@code secretKey} parameters must comply with the following:
		 * <ul>
		 *     <li>the ciphertext and the secret key must belong to groups of same order.</li>
		 *     <li>the ciphertext size must be at most the secret key size.</li>
		 * </ul>
		 *
		 * @param ciphertext c,	the ciphertext to be decrypted. Must be non null.
		 * @param secretKey  sk, the secret key to be used for decrypting. Must be non null and not empty.
		 * @return the decrypted plaintext message
		 */
	ElGamalMultiRecipientMessage getMessage(final ElGamalMultiRecipientCiphertext ciphertext, final ElGamalMultiRecipientPrivateKey secretKey);

	/**
	 * Generates an {@link ElGamalMultiRecipientMessage} of ones.
	 *
	 * @param group the {@link GqGroup} of the message
	 * @param size  the number of ones to be contained in the message
	 * @return the message (1, ..., 1) with {@code size} elements
	 */
	ElGamalMultiRecipientMessage ones(final GqGroup group, final int size);

	/**
	 * Picks encryption parameters for the given seed.
	 *
	 * @param seed the seed used for the parameters generation.
	 * @return a {@link GqGroup} containing parameters p, q and g.
	 */
	GqGroup getEncryptionParameters(final String seed);

	/**
	 * Generates a key pair in the specified group and with the specified number of elements.
	 *
	 * @param group         The {@link GqGroup} in which to generate the public keys. Not null.
	 * @param numElements,  N, the number of elements that each key (the public key and the private key) should be composed of. This value must be
	 *                      greater than 0.
	 * @param random a service providing randomness. Not null.
	 * @return the generated key pair.
	 */
	ElGamalMultiRecipientKeyPair genKeyPair(final GqGroup group, final int numElements, final Random random);

	/**
	 * Returns a key pair containing the {@code private key} and its derived public key with the given {@code generator}.
	 * <p>
	 * The private key and the generator must comply with the following:
	 *  <ul>
	 *      <li>Must belong to groups of the same order.</li>
	 * </ul>
	 *
	 * @param privateKey the private key from which the public key must be derived. Must be non-null and non-empty.
	 * @param generator  the group generator to be used for the public key derivation. Must be non-null.
	 * @return a key pair containing the private key and the derived public key.
	 */
	ElGamalMultiRecipientKeyPair from(final ElGamalMultiRecipientPrivateKey privateKey, final GqElement generator);

	/**
	 * Combines the public keys by multiplying them element wise.
	 *
	 * @param publicKeyList (pk<sub>0</sub>, ..., pk<sub>s</sub>), the list of public keys to be combined. Must be non-null.
	 * @return the combined public key
	 */
	ElGamalMultiRecipientPublicKey combinePublicKeys(final GroupVector<ElGamalMultiRecipientPublicKey, GqGroup> publicKeyList);
}
