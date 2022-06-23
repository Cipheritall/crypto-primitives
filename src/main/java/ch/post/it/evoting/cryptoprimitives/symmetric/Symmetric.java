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

import java.util.List;

import ch.post.it.evoting.cryptoprimitives.internal.symmetric.SymmetricAuthenticatedEncryptionService;

/**
 * Provides methods for symmetric encryption/decryption.
 */
public interface Symmetric {

	/**
	 * Symmetric authenticated encryption scheme based on authenticated Encryption with Associated Data (AEAD)
	 *
	 * @param encryptionKey  K ∈ B<sup>k</sup>. Not null.
	 * @param plaintext      P ∈ B<sup>p</sup>. Not null.
	 * @param associatedData (associated<sub>0</sub>,....,associated<sub>n-1</sub>) ∈ A<sub>UCS</sub><sup>*</sup>)<sup>n</sup>, s.t. n ∈ N. Not null.
	 * @return The authenticated ciphertext C ∈ B<sup>c</sup> and the nonce ∈ B<sup>n</sup>.
	 * @throws IllegalArgumentException if the given encryptionKey is invalid for this underlying algorithm.
	 */
	SymmetricCiphertext genCiphertextSymmetric(final byte[] encryptionKey, final byte[] plaintext, final List<String> associatedData);

	/**
	 * Symmetric authenticated decryption scheme based on authenticated Decryption with Associated Data (AEAD)
	 *
	 * @param encryptionKey  K ∈ B<sup>k</sup>. Not null.
	 * @param ciphertext     C ∈ B<sup>c</sup>. Not null.
	 * @param nonce          nonce ∈ B<sup>n</sup>. Not null.
	 * @param associatedData (associated<sub>0</sub>,....,associated<sub>n-1</sub>) ∈ A<sub>UCS</sub><sup>*</sup>)<sup>n</sup>, s.t. n ∈ N. Not null.
	 * @return The authenticated plaintext P ∈ B<sup>p</sup>. Throws an exception if the ciphertext does not authenticate.
	 * @throws IllegalArgumentException if
	 *                                  <ul>
	 *                                      <li>the given encryptionKey is invalid for this underlying algorithm.</li>
	 *                                      <li>the nonce does not match the expected format.</li>
	 *                                  </ul>
	 */
	byte[] getPlaintextSymmetric(final byte[] encryptionKey, final byte[] ciphertext, final byte[] nonce, final List<String> associatedData);

	/**
	 * Provides the nonce length of {@link SymmetricAuthenticatedEncryptionService.SymmetricEncryptionAlgorithm} algorithm used to initialize the
	 * service.
	 *
	 * @return the nonce length value.
	 */
	int getNonceLength();

}
