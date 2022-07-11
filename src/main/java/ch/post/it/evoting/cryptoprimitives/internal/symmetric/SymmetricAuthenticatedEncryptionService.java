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
package ch.post.it.evoting.cryptoprimitives.internal.symmetric;

import static ch.post.it.evoting.cryptoprimitives.internal.utils.ConversionsInternal.stringToByteArray;
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

import ch.post.it.evoting.cryptoprimitives.internal.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.symmetric.Symmetric;
import ch.post.it.evoting.cryptoprimitives.symmetric.SymmetricCiphertext;
import ch.post.it.evoting.cryptoprimitives.utils.Conversions;

@SuppressWarnings({ "java:S116", "java:S117" })
public class SymmetricAuthenticatedEncryptionService {

	private final RandomService randomService;
	private final SymmetricEncryptionAlgorithm algorithm;

	SymmetricAuthenticatedEncryptionService(final RandomService randomService, final SymmetricEncryptionAlgorithm algorithm) {
		this.randomService = checkNotNull(randomService);
		this.algorithm = checkNotNull(algorithm);
	}

	/**
	 * @see Symmetric#getNonceLength()
	 */
	int getNonceLength() {
		return algorithm.nonceLength;
	}

	/**
	 * @see Symmetric#genCiphertextSymmetric(byte[], byte[], List)
	 */
	SymmetricCiphertext genCiphertextSymmetric(final byte[] encryptionKey, final byte[] plaintext, final List<String> associatedData) {

		checkNotNull(encryptionKey);
		checkNotNull(plaintext);
		checkNotNull(associatedData);
		checkArgument(associatedData.stream().allMatch(Objects::nonNull), "The associated data must not contain null objects.");

		final List<String> associated_vector = List.copyOf(associatedData);
		associated_vector.forEach(associated_i -> checkArgument(stringToByteArray(associated_i).length <= 255,
				"The required length of each associated data must be smaller or equal to 255."));

		// Context.
		final byte[] K = encryptionKey;
		final byte[] P = plaintext;

		// Operation.
		final byte[] nonce = randomService.randomBytes(this.algorithm.nonceLength);
		final byte[] associated =
				Bytes.concat(
						associated_vector.stream()
								.map(Conversions::stringToByteArray)
								.map(associated_i_bytes -> Bytes.concat(new byte[] { (byte) associated_i_bytes.length }, associated_i_bytes))
								.toArray(byte[][]::new)
				);
		final byte[] C = authenticatedEncryption(K, nonce, P, associated);

		// Compute C.
		return new SymmetricCiphertext(C, nonce);
	}

	/**
	 * @see Symmetric#getPlaintextSymmetric(byte[], byte[], byte[], List)
	 */
	byte[] getPlaintextSymmetric(final byte[] encryptionKey, final byte[] ciphertext, final byte[] nonce, final List<String> associatedData) {

		checkNotNull(encryptionKey);
		checkNotNull(ciphertext);
		checkNotNull(nonce);
		checkNotNull(associatedData);
		checkArgument(associatedData.stream().allMatch(Objects::nonNull), "The associated data must not contain null objects.");

		final List<String> associated_vector = List.copyOf(associatedData);
		associated_vector.forEach(associated_i -> checkArgument(stringToByteArray(associated_i).length <= 255,
				"The required length of each associated data must be smaller or equal to 255."));

		// Context.
		final byte[] K = encryptionKey;
		final byte[] C = ciphertext;

		// Operation.
		final byte[] associated =
				Bytes.concat(
						associatedData.stream()
								.map(Conversions::stringToByteArray)
								.map(associated_i_bytes -> Bytes.concat(new byte[] { (byte) associated_i_bytes.length }, associated_i_bytes))
								.toArray(byte[][]::new)
				);

		// Compute P.
		return authenticatedDecryption(K, nonce, associated, C);
	}

	byte[] authenticatedEncryption(final byte[] encryptionKey, final byte[] nonce, final byte[] plaintext, final byte[] associatedData) {

		final Cipher cipher;
		try {
			cipher = getCipher(encryptionKey, nonce, Cipher.ENCRYPT_MODE);
		} catch (final InvalidAlgorithmParameterException e) {
			throw new IllegalStateException("Configured algorithm parameters are invalid or inappropriate.", e);
		}

		cipher.updateAAD(associatedData);

		try {
			return cipher.doFinal(plaintext);
		} catch (final BadPaddingException e) {
			throw new IllegalStateException("We should never get this exception since it is only thrown in decryption mode.");
		} catch (final IllegalBlockSizeException e) {
			throw new IllegalStateException("We should never get this exception since our algorithm is not a block cipher.");
		}
	}

	byte[] authenticatedDecryption(final byte[] encryptionKey, final byte[] nonce, final byte[] associatedData, final byte[] ciphertext) {

		final Cipher cipher;
		try {
			cipher = getCipher(encryptionKey, nonce, Cipher.DECRYPT_MODE);
		} catch (final InvalidAlgorithmParameterException e) {
			throw new IllegalArgumentException("Error with the given nonce during Cipher initialization", e);
		}

		cipher.updateAAD(associatedData);

		try {
			return cipher.doFinal(ciphertext);
		} catch (final BadPaddingException e) {
			throw new IllegalStateException("We should never get this exception since no padding is needed for the configured algorithm.", e);
		} catch (final IllegalBlockSizeException e) {
			throw new IllegalStateException("We should never get this exception since our algorithm is not a block cipher.", e);
		}
	}

	private Cipher getCipher(final byte[] encryptionKey, final byte[] nonce, final int opmode)
			throws InvalidAlgorithmParameterException {
		// Get Cipher Instance
		final Cipher cipher;
		try {
			cipher = Cipher.getInstance(this.algorithm.getAlgorithmName());
		} catch (final NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new IllegalStateException("Requested cryptographic algorithm or padding in the algorithm is not available in the environment.", e);
		}

		// Create the encryptionKey
		final Key key = this.algorithm.getKey(encryptionKey);

		// Create the algorithm used for the authentication
		final AlgorithmParameterSpec params = this.algorithm.getAlgorithmParameterSpec(nonce);

		// Initialize Cipher for the authentication
		try {
			cipher.init(opmode, key, params);
		} catch (final InvalidKeyException e) {
			throw new IllegalArgumentException("Error with the given encryptionKey during Cipher initialization", e);
		}

		return cipher;
	}

	public enum SymmetricEncryptionAlgorithm {
		AES256_GCM_NOPADDING("AES_256/GCM/NoPadding", 12,
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

}
