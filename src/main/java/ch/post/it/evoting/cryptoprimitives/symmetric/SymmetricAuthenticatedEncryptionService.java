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
package ch.post.it.evoting.cryptoprimitives.symmetric;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.google.common.primitives.Bytes;

import ch.post.it.evoting.cryptoprimitives.ConversionService;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;

@SuppressWarnings({ "java:S116", "java:S117" })
public class SymmetricAuthenticatedEncryptionService {

	private final RandomService randomService;
	private final SymmetricEncryptionAlgorithm algorithm;

	SymmetricAuthenticatedEncryptionService(final RandomService randomService, final SymmetricEncryptionAlgorithm algorithm) {
		this.randomService = checkNotNull(randomService);
		this.algorithm = checkNotNull(algorithm);
	}

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
			BadPaddingException, InvalidKeyException {

		checkNotNull(encryptionKey);
		checkNotNull(plainText);
		checkNotNull(associatedData);
		checkArgument(associatedData.stream().allMatch(Objects::nonNull), "The associated data must not contain null objects.");

		// Context.
		final byte[] K = encryptionKey;
		final byte[] P = plainText;

		// Operation.
		final byte[] nonce = randomService.randomBytes(this.algorithm.nonceLength);
		final byte[] associated =
				Bytes.concat(
						associatedData.stream()
								.map(ConversionService::stringToByteArray)
								.toArray(byte[][]::new)
				);
		final byte[] C = authenticatedEncryption(K, nonce, P, associated);

		// Compute C.
		return new SymmetricCiphertext(C, nonce);
	}

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
	byte[] getPlaintextSymmetric(final byte[] encryptionKey, final byte[] cipherText, final byte[] nonce,
			final List<String> associatedData)
			throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
			BadPaddingException, InvalidKeyException {

		checkNotNull(encryptionKey);
		checkNotNull(cipherText);
		checkNotNull(nonce);
		checkNotNull(associatedData);
		checkArgument(associatedData.stream().allMatch(Objects::nonNull), "The associated data must not contain null objects.");

		// Context.
		final byte[] K = encryptionKey;
		final byte[] C = cipherText;

		// Operation.
		final byte[] associated =
				Bytes.concat(
						associatedData.stream()
								.map(ConversionService::stringToByteArray)
								.toArray(byte[][]::new)
				);

		// Compute P.
		return authenticatedDecryption(K, nonce, associated, C);
	}

	byte[] authenticatedEncryption(final byte[] encryptionKey, final byte[] nonce, final byte[] plaintext, final byte[] associatedData)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {

		final Cipher cipher = getCipher(encryptionKey, nonce, Cipher.ENCRYPT_MODE);

		cipher.updateAAD(associatedData);

		return cipher.doFinal(plaintext);
	}

	byte[] authenticatedDecryption(final byte[] encryptionKey, final byte[] nonce, final byte[] associatedData, final byte[] cipherText)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {

		final Cipher cipher = getCipher(encryptionKey, nonce, Cipher.DECRYPT_MODE);

		cipher.updateAAD(associatedData);

		return cipher.doFinal(cipherText);
	}

	private Cipher getCipher(final byte[] encryptionKey, final byte[] nonce, final int opmode)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		// Get Cipher Instance
		final Cipher cipher = Cipher.getInstance(this.algorithm.getAlgorithmName());

		// Create the encryptionKey
		final Key key = this.algorithm.getKey(encryptionKey);

		// Create the algorithm used for the authentication
		final AlgorithmParameterSpec algorithmParameterSpec = this.algorithm.getAlgorithmParameterSpec(nonce);

		// Initialize Cipher for the authentication
		cipher.init(opmode, key, algorithmParameterSpec);

		return cipher;
	}

	public enum SymmetricEncryptionAlgorithm {
		AES_GCM_NOPADDING("AES/GCM/NoPadding", 12,
				(byte[] nonce) -> new GCMParameterSpec(SymmetricEncryptionAlgorithm.AES_GCM_TAG_LENGTH * 8, nonce),
				(byte[] key) -> new SecretKeySpec(key, "AES"));

		private static final int AES_GCM_TAG_LENGTH = 16;

		private final String algorithmName;
		private final int nonceLength;
		private final Function<byte[], AlgorithmParameterSpec> parameterSpecFunction;
		private final Function<byte[], Key> keyTransformer;

		SymmetricEncryptionAlgorithm(final String algorithmName, final int nonceLength,
				final Function<byte[], AlgorithmParameterSpec> parameterSpecFunction,
				final Function<byte[], Key> keyTransformer) {
			this.algorithmName = algorithmName;
			this.nonceLength = nonceLength;
			this.parameterSpecFunction = parameterSpecFunction;
			this.keyTransformer = keyTransformer;
		}

		public AlgorithmParameterSpec getAlgorithmParameterSpec(final byte[] nonce) {
			checkArgument(nonce.length == nonceLength, String.format("Invalid nonce length, expected %s", nonceLength));
			return this.parameterSpecFunction.apply(nonce);
		}

		public Key getKey(final byte[] encryptionKey) {
			return keyTransformer.apply(encryptionKey);
		}

		public String getAlgorithmName() {
			return algorithmName;
		}
	}

	static class SymmetricCiphertext {
		final byte[] C;
		final byte[] nonce;

		SymmetricCiphertext(final byte[] C, final byte[] nonce) {

			this.C = checkNotNull(C);
			this.nonce = checkNotNull(nonce);

		}
	}

}
