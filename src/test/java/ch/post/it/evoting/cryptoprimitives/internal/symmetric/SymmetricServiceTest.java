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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

import javax.crypto.KeyGenerator;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import com.google.common.base.Throwables;

import ch.post.it.evoting.cryptoprimitives.internal.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.symmetric.SymmetricCiphertext;
import ch.post.it.evoting.cryptoprimitives.test.tools.TestGroupSetup;

@DisplayName("SymmetricService calling")
class SymmetricServiceTest extends TestGroupSetup {

	private static final int AES_KEY_SIZE = 256;
	private static final int DIFFERENT_AES_KEY_SIZE = 128;
	private static final int NONCE_LENGTH = 12;
	private static final int DIFFERENT_NONCE_LENGTH = 96;
	private static final int ASSOCIATED_LENGTH = 4;
	private static final int PLAINTEXT_LENGTH = 96;

	private static byte[] encryptionKey;
	private static byte[] nonce;
	private static String plainText;
	private static RandomService randomService;
	private static SymmetricService symmetricEncryptionService;
	private static List<String> associatedData;

	@BeforeAll
	static void setUpAll() throws NoSuchAlgorithmException {
		randomService = new RandomService();
		symmetricEncryptionService = new SymmetricService(randomService);

		final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(AES_KEY_SIZE);

		// Generate encryptionKey
		encryptionKey = keyGenerator.generateKey().getEncoded();
	}

	@BeforeEach
	void setUp() {
		associatedData = Arrays.asList(randomService.genRandomBase16String(ASSOCIATED_LENGTH), randomService.genRandomBase64String(
				ASSOCIATED_LENGTH));
		plainText = randomService.genRandomBase64String(PLAINTEXT_LENGTH);
		nonce = randomService.randomBytes(NONCE_LENGTH);
	}

	@Test
	@DisplayName("valid parameters does not throw, basic encryption path with Java AES 256 GCM Encryption Algorithm")
	void basicJavaAES256GCMEncryptionPath() {
		final SymmetricCiphertext authenticationEncrypted = symmetricEncryptionService.genCiphertextSymmetric(
				encryptionKey, plainText.getBytes(StandardCharsets.UTF_8), associatedData);

		final byte[] authenticationDecrypted = symmetricEncryptionService.getPlaintextSymmetric(encryptionKey,
				authenticationEncrypted.getCiphertext(), authenticationEncrypted.getNonce(), associatedData);

		assertEquals(plainText, new String(authenticationDecrypted, StandardCharsets.UTF_8));
	}

	@Test
	@DisplayName("wrong parameters throws illegalArgumentException, basic encryption path with Java AES 256 GCM Encryption Algorithm")
	void wrongEncryptionInvalidNonceLength() {
		// Different nonce between encryption and decryption execute 'Invalid nonce length'!
		final SymmetricCiphertext authenticationEncrypted = symmetricEncryptionService.genCiphertextSymmetric(
				encryptionKey, plainText.getBytes(StandardCharsets.UTF_8), associatedData);

		nonce = randomService.randomBytes(DIFFERENT_NONCE_LENGTH);

		final byte[] ciphertext = authenticationEncrypted.getCiphertext();
		final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> symmetricEncryptionService.getPlaintextSymmetric(encryptionKey, ciphertext, nonce, associatedData));

		assertEquals("Invalid nonce length, expected 12", Throwables.getRootCause(illegalArgumentException).getMessage());
	}

	@Test
	@DisplayName("wrong encryption key length throws illegalArgumentException, basic encryption path with Java AES 256 GCM Encryption Algorithm")
	void wrongEncryptionInvalidKeyLength() {

		final byte[] differentEncryptionKey = randomService.randomBytes(DIFFERENT_AES_KEY_SIZE / 8);

		final byte[] plainTextBytes = plainText.getBytes(StandardCharsets.UTF_8);
		final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> symmetricEncryptionService.genCiphertextSymmetric(differentEncryptionKey, plainTextBytes, associatedData));

		assertEquals("The key must be 32 bytes", Throwables.getRootCause(illegalArgumentException).getMessage());
	}

	@Nested
	@DisplayName("genCiphertextSymmetric with")
	class GenCiphertextSymmetric {

		@Test
		@DisplayName("null parameters throws NullPointerException")
		void nullParams() {
			final byte[] plainTextBytes = plainText.getBytes(StandardCharsets.UTF_8);

			assertThrows(NullPointerException.class,
					() -> symmetricEncryptionService.genCiphertextSymmetric(null, plainTextBytes,
							associatedData));
			assertThrows(NullPointerException.class,
					() -> symmetricEncryptionService.genCiphertextSymmetric(encryptionKey, null,
							associatedData));
			assertThrows(NullPointerException.class,
					() -> symmetricEncryptionService.genCiphertextSymmetric(encryptionKey, plainTextBytes,
							null));
		}

		@Test
		@DisplayName("Associated data containing null throws IllegalArgumentException")
		void associatedDataWithNull() {
			associatedData.set(0, null);
			final byte[] plainTextBytes = plainText.getBytes(StandardCharsets.UTF_8);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> symmetricEncryptionService
					.genCiphertextSymmetric(encryptionKey, plainTextBytes,
							associatedData));
			assertEquals("The associated data must not contain null objects.", exception.getMessage());
		}
	}

	@Nested
	@DisplayName("getPlaintextSymmetric with")
	class GetPlaintextSymmetric {

		@Test
		@DisplayName("null parameters throws NullPointerException")
		void nullParams() {
			final SymmetricCiphertext authenticationEncrypted = symmetricEncryptionService.genCiphertextSymmetric(
					encryptionKey, plainText.getBytes(StandardCharsets.UTF_8), associatedData);

			final byte[] ciphertext = authenticationEncrypted.getCiphertext();
			final byte[] nonce = authenticationEncrypted.getNonce();
			assertThrows(NullPointerException.class,
					() -> symmetricEncryptionService.getPlaintextSymmetric(null, ciphertext, nonce, associatedData));
			assertThrows(NullPointerException.class,
					() -> symmetricEncryptionService.getPlaintextSymmetric(encryptionKey, null, nonce, associatedData));
			assertThrows(NullPointerException.class,
					() -> symmetricEncryptionService.getPlaintextSymmetric(encryptionKey, ciphertext, null, associatedData));
			assertThrows(NullPointerException.class,
					() -> symmetricEncryptionService.getPlaintextSymmetric(encryptionKey, ciphertext, nonce, null));
		}

		@Test
		@DisplayName("Associated data containing null throws IllegalArgumentException")
		void associatedDataWithNull() {
			associatedData.set(0, null);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> symmetricEncryptionService.getPlaintextSymmetric(encryptionKey, new byte[] {}, new byte[] {}, associatedData));

			assertEquals("The associated data must not contain null objects.", exception.getMessage());
		}
	}

	@Test
	@DisplayName("getNonceLength")
	void nonceLength() {
		assertEquals(NONCE_LENGTH, symmetricEncryptionService.getNonceLength());
	}

	@Test
	@DisplayName("call default constructor")
	void defaultConstructor() {
		assertDoesNotThrow(() -> new SymmetricService());
	}
}
