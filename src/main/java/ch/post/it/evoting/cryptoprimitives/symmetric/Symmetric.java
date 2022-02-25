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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * Provides methods for symmetric encryption/decryption.
 */
public interface Symmetric {

	/**
	 * Symmetric authenticated encryption scheme based on authenticated Encryption with Associated Data (AEAD)
	 *
	 * @param encryptionKey  K ∈ B<sup>k</sup>. Not null.
	 * @param plainText      P ∈ B<sup>p</sup>. Not null.
	 * @param associatedData (associated<sub>0</sub>,....,associated<sub>n-1</sub>) ∈ A<sub>UCS</sub><sup>*</sup>)<sup>n</sup>, s.t. n ∈ N. Not null.
	 * @return The authenticated plaintext P ∈ B<sup>p</sup>. Throws an exception if the ciphertext does not authenticate
	 * @throws InvalidAlgorithmParameterException if algorithm parameters are invalid or inappropriate.
	 * @throws NoSuchPaddingException             if padding requested in the algorithm is not available in the environment.
	 * @throws IllegalBlockSizeException          if the length of data provided to the cipher block is incorrect, i.e., does not match the block size
	 *                                            of the cipher.
	 * @throws NoSuchAlgorithmException           if the cryptographic algorithm requested is not available in the environment.
	 * @throws BadPaddingException                if padding mechanism expected for the input data is not padded properly.
	 * @throws InvalidKeyException                if there are invalid Keys (invalid encoding, wrong length, uninitialized, etc).
	 */
	SymmetricCiphertext genCiphertextSymmetric(final byte[] encryptionKey, final byte[] plainText,
			final List<String> associatedData)
			throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
			BadPaddingException, InvalidKeyException;

	/**
	 * Symmetric authenticated decryption scheme based on authenticated Decryption with Associated Data (AEAD)
	 *
	 * @param encryptionKey  K ∈ B<sup>k</sup>. Not null.
	 * @param cipherText     C ∈ B<sup>c</sup>. Not null.
	 * @param nonce          nonce ∈ B<sup>n</sup>. Not null.
	 * @param associatedData (associated<sub>0</sub>,....,associated<sub>n-1</sub>) ∈ A<sub>UCS</sub><sup>*</sup>)<sup>n</sup>, s.t. n ∈ N. Not null.
	 * @return plaintextSymmetric - AuthenticatedDecryption(K,nonce,associated,C)
	 * @throws InvalidAlgorithmParameterException if algorithm parameters are invalid or inappropriate.
	 * @throws NoSuchPaddingException             if padding requested in the algorithm is not available in the environment.
	 * @throws IllegalBlockSizeException          if the length of data provided to the cipher block is incorrect, i.e., does not match the block size
	 *                                            of the cipher.
	 * @throws NoSuchAlgorithmException           if the cryptographic algorithm requested is not available in the environment.
	 * @throws BadPaddingException                if padding mechanism expected for the input data is not padded properly.
	 * @throws InvalidKeyException                if where are invalid Keys (invalid encoding, wrong length, uninitialized, etc).
	 */
	byte[] getPlaintextSymmetric(final byte[] encryptionKey, final byte[] cipherText,
			final byte[] nonce,
			final List<String> associatedData)
			throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
			BadPaddingException, InvalidKeyException;

}
