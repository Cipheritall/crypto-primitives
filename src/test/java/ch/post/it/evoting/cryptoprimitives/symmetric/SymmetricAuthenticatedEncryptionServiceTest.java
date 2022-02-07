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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

import javax.crypto.AEADBadTagException;
import javax.crypto.KeyGenerator;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import com.google.common.base.Throwables;

import ch.post.it.evoting.cryptoprimitives.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;

@DisplayName("SymmetricAuthenticatedEncryptionService calling")
class SymmetricAuthenticatedEncryptionServiceTest extends TestGroupSetup {

	private static final int AES_KEY_SIZE = 256;
	private static final int NONCE_LENGTH = 12;
	private static final int DIFFERENT_NONCE_LENGTH = 96;
	private static final int ASSOCIATED_LENGTH = 4;
	private static final int PLAINTEXT_LENGTH = 96;

	private static byte[] encryptionKey;
	private static byte[] nonce;
	private static String plainText;
	private static RandomService randomService;
	private static SymmetricAuthenticatedEncryptionService symmetricAuthenticatedEncryptionService;
	private static List<String> associatedData;

	@BeforeAll
	static void setUpAll() throws NoSuchAlgorithmException {
		randomService = new RandomService();
		symmetricAuthenticatedEncryptionService = new SymmetricAuthenticatedEncryptionService(randomService,
				SymmetricAuthenticatedEncryptionService.SymmetricEncryptionAlgorithm.AES_GCM_NOPADDING);

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
	void basicJavaAES256GCMEncryptionPath() throws Exception {
		final SymmetricAuthenticatedEncryptionService.SymmetricCiphertext authenticationEncrypted = symmetricAuthenticatedEncryptionService.genCiphertextSymmetric(
				encryptionKey, plainText.getBytes(StandardCharsets.UTF_8), associatedData);

		final byte[] authenticationDecrypted = symmetricAuthenticatedEncryptionService.getPlaintextSymmetric(encryptionKey, authenticationEncrypted.C,
				authenticationEncrypted.nonce, associatedData);

		assertEquals(plainText, new String(authenticationDecrypted, StandardCharsets.UTF_8));
	}

	@Test
	@DisplayName("wrong parameters throws illegalArgumentException, basic encryption path with Java AES 256 GCM Encryption Algorithm")
	void wrongEncryptionInvalidNonceLength() throws Exception {
		// Different nonce between encryption and decryption execute 'Invalid nonce length'!
		final SymmetricAuthenticatedEncryptionService.SymmetricCiphertext authenticationEncrypted = symmetricAuthenticatedEncryptionService.genCiphertextSymmetric(
				encryptionKey, plainText.getBytes(StandardCharsets.UTF_8), associatedData);

		nonce = randomService.randomBytes(DIFFERENT_NONCE_LENGTH);

		final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> symmetricAuthenticatedEncryptionService.getPlaintextSymmetric(encryptionKey, authenticationEncrypted.C, nonce, associatedData));

		assertEquals("Invalid nonce length, expected 12", Throwables.getRootCause(illegalArgumentException).getMessage());
	}

	@Test
	@DisplayName("wrong parameters throws AEADBadTagException, basic encryption path with Java AES 256 GCM Encryption Algorithm")
	void wrongEncryptionTagMismatch() throws Exception {
		// Different nonce between encryption and decryption execute Tag mismatch!
		final SymmetricAuthenticatedEncryptionService.SymmetricCiphertext authenticationEncrypted = symmetricAuthenticatedEncryptionService.genCiphertextSymmetric(
				encryptionKey, plainText.getBytes(StandardCharsets.UTF_8), associatedData);

		final AEADBadTagException aeadBadTagException = assertThrows(AEADBadTagException.class,
				() -> symmetricAuthenticatedEncryptionService.getPlaintextSymmetric(encryptionKey, authenticationEncrypted.C,
						nonce, associatedData));

		assertEquals("Tag mismatch!", aeadBadTagException.getMessage());
	}

	@Nested
	@DisplayName("genCiphertextSymmetric with")
	class GenCiphertextSymmetric {

		@Test
		@DisplayName("null parameters throws NullPointerException")
		void nullParams() {
			final byte[] plainTextBytes = plainText.getBytes(StandardCharsets.UTF_8);

			assertThrows(NullPointerException.class,
					() -> symmetricAuthenticatedEncryptionService.genCiphertextSymmetric(null, plainTextBytes,
							associatedData));
			assertThrows(NullPointerException.class,
					() -> symmetricAuthenticatedEncryptionService.genCiphertextSymmetric(encryptionKey, null,
							associatedData));
			assertThrows(NullPointerException.class,
					() -> symmetricAuthenticatedEncryptionService.genCiphertextSymmetric(encryptionKey, plainTextBytes,
							null));
		}

		@Test
		@DisplayName("Associated data containing null throws IllegalArgumentException")
		void associatedDataWithNull() {
			associatedData.set(0, null);
			final byte[] plainTextBytes = plainText.getBytes(StandardCharsets.UTF_8);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> symmetricAuthenticatedEncryptionService
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
		void nullParams() throws Exception {
			final SymmetricAuthenticatedEncryptionService.SymmetricCiphertext authenticationEncrypted = symmetricAuthenticatedEncryptionService.genCiphertextSymmetric(
					encryptionKey, plainText.getBytes(StandardCharsets.UTF_8), associatedData);

			assertThrows(NullPointerException.class,
					() -> symmetricAuthenticatedEncryptionService.getPlaintextSymmetric(null, authenticationEncrypted.C,
							authenticationEncrypted.nonce, associatedData));
			assertThrows(NullPointerException.class,
					() -> symmetricAuthenticatedEncryptionService.getPlaintextSymmetric(encryptionKey, null,
							authenticationEncrypted.nonce, associatedData));
			assertThrows(NullPointerException.class,
					() -> symmetricAuthenticatedEncryptionService.getPlaintextSymmetric(encryptionKey, authenticationEncrypted.C,
							null, associatedData));
			assertThrows(NullPointerException.class,
					() -> symmetricAuthenticatedEncryptionService.getPlaintextSymmetric(encryptionKey, authenticationEncrypted.C,
							authenticationEncrypted.nonce, null));
		}

		@Test
		@DisplayName("Associated data containing null throws IllegalArgumentException")
		void associatedDataWithNull() {
			associatedData.set(0, null);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> symmetricAuthenticatedEncryptionService.getPlaintextSymmetric(encryptionKey, new byte[] {}, new byte[] {}, associatedData));

			assertEquals("The associated data must not contain null objects.", exception.getMessage());
		}
	}
}