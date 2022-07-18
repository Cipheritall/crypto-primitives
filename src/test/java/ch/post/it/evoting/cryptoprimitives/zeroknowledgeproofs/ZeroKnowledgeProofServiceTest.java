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

import static ch.post.it.evoting.cryptoprimitives.math.GqElement.GqElementFactory;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamal;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientKeyPair;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPrivateKey;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.internal.elgamal.ElGamalService;
import ch.post.it.evoting.cryptoprimitives.internal.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.internal.hashing.TestHashService;
import ch.post.it.evoting.cryptoprimitives.internal.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.internal.zeroknowledgeproofs.ZeroKnowledgeProofService;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;

class ZeroKnowledgeProofServiceTest extends TestGroupSetup {

	private static final ElGamal elGamal = new ElGamalService();
	private static final SecureRandom random = new SecureRandom();
	private static final RandomService randomService = new RandomService();

	private ZeroKnowledgeProof zeroKnowledgeProofservice;
	private ElGamalGenerator elGamalGenerator;

	private int numCiphertexts;
	private int keyLength;
	private int ciphertextLength;
	private GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts;
	private ElGamalMultiRecipientKeyPair keyPair;
	private List<String> auxiliaryInformation;

	@BeforeEach
	void setup() {
		HashService hashService = TestHashService.create(gqGroup.getQ());
		zeroKnowledgeProofservice = new ZeroKnowledgeProofService(randomService, hashService);
		elGamalGenerator = new ElGamalGenerator(gqGroup);

		final int maxLength = 10;
		numCiphertexts = random.nextInt(maxLength) + 1;
		keyLength = random.nextInt(maxLength) + 1;
		ciphertextLength = random.nextInt(keyLength) + 1;
		ciphertexts = elGamalGenerator.genRandomCiphertextVector(numCiphertexts, ciphertextLength);
		keyPair = elGamal.genKeyPair(gqGroup, keyLength, randomService);
		auxiliaryInformation = Arrays.asList("a", "b");
	}

	@Nested
	class GenVerifiableDecryptionsTest {
		@Test
		@DisplayName("Generating verifiable decryptions with null arguments throws a NullPointerException")
		void genVerifiableDecryptionsWithNullArguments() {
			assertThrows(NullPointerException.class, () -> zeroKnowledgeProofservice.genVerifiableDecryptions(null, keyPair, auxiliaryInformation));
			assertThrows(NullPointerException.class,
					() -> zeroKnowledgeProofservice.genVerifiableDecryptions(ciphertexts, null, auxiliaryInformation));
			assertThrows(NullPointerException.class, () -> zeroKnowledgeProofservice.genVerifiableDecryptions(ciphertexts, keyPair, null));
		}

		@Test
		@DisplayName("Generating verifiable decryptions with valid arguments does not throw")
		void genVerifiableDecryptionsWithValidArguments() {
			assertDoesNotThrow(() -> zeroKnowledgeProofservice.genVerifiableDecryptions(ciphertexts, keyPair, List.of()));
			assertDoesNotThrow(() -> zeroKnowledgeProofservice.genVerifiableDecryptions(ciphertexts, keyPair, auxiliaryInformation));
		}

		@Test
		@DisplayName("Generating verifiable decryptions with an empty list ciphertexts throws an IllegalArgumentException")
		void genVerifiableDecryptionsWithEmptyCiphertextList() {
			ciphertexts = GroupVector.of();
			IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroKnowledgeProofservice.genVerifiableDecryptions(ciphertexts, keyPair, auxiliaryInformation));
			assertEquals("There must be at least one ciphertext.", exception.getMessage());
		}

		@Test
		@DisplayName("Generating verifiable decryptions with too long ciphertexts throws an IllegalArgumentException")
		void genVerifiableDecryptionsWithTooLongCiphertexts() {
			ciphertexts = elGamalGenerator.genRandomCiphertextVector(numCiphertexts, keyLength + 1);
			IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroKnowledgeProofservice.genVerifiableDecryptions(ciphertexts, keyPair, auxiliaryInformation));
			assertEquals("The ciphertexts must be at most as long as the keys in the key pair.", exception.getMessage());
		}

		@Test
		@DisplayName("Generating verifiable decryptions with ciphertexts and keys from different groups throws an IllegalArgumentException")
		void genVerifiableDecryptionsWithIncompatibleGroups() {
			ciphertexts = new ElGamalGenerator(otherGqGroup).genRandomCiphertextVector(numCiphertexts, ciphertextLength);
			IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroKnowledgeProofservice.genVerifiableDecryptions(ciphertexts, keyPair, auxiliaryInformation));
			assertEquals("The ciphertexts and the key pair must have the same group.", exception.getMessage());
		}
	}

	@Nested
	class VerifyDecryptionsTest {

		ElGamalMultiRecipientPublicKey publicKey;
		VerifiableDecryptions verifiableDecryptions;
		VerifiableDecryptions verifiableDecryptionsEmptyAux;

		@BeforeEach
		void setup() {
			publicKey = keyPair.getPublicKey();
			verifiableDecryptions = zeroKnowledgeProofservice.genVerifiableDecryptions(ciphertexts, keyPair, auxiliaryInformation);
			verifiableDecryptionsEmptyAux = zeroKnowledgeProofservice.genVerifiableDecryptions(ciphertexts, keyPair, List.of());
		}

		@Test
		@DisplayName("Verifying decryptions with null arguments throws a NullPointerException")
		void verifyDecryptionsWithNullArguments() {
			assertThrows(NullPointerException.class,
					() -> zeroKnowledgeProofservice.verifyDecryptions(null, publicKey, verifiableDecryptions, auxiliaryInformation));
			assertThrows(NullPointerException.class,
					() -> zeroKnowledgeProofservice.verifyDecryptions(ciphertexts, null, verifiableDecryptions, auxiliaryInformation));
			assertThrows(NullPointerException.class,
					() -> zeroKnowledgeProofservice.verifyDecryptions(ciphertexts, publicKey, null, auxiliaryInformation));
			assertThrows(NullPointerException.class,
					() -> zeroKnowledgeProofservice.verifyDecryptions(ciphertexts, publicKey, verifiableDecryptions, null));
		}

		@Test
		@DisplayName("Verifying decryptions with valid inputs does not throw")
		void verifyDecryptionsWithValidInput() {
			Boolean result = assertDoesNotThrow(
					() -> zeroKnowledgeProofservice.verifyDecryptions(ciphertexts, publicKey, verifiableDecryptions, auxiliaryInformation)
							.isVerified());
			assertTrue(result);

			result = assertDoesNotThrow(
					() -> zeroKnowledgeProofservice.verifyDecryptions(ciphertexts, publicKey, verifiableDecryptionsEmptyAux, List.of())
							.isVerified());
			assertTrue(result);
		}

		@Test
		@DisplayName("Verifying decryptions with ciphertexts from different group throws an IllegalArgumentException")
		void verifyDecryptionsWithOtherCiphertexts() {
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> otherCiphertexts = new ElGamalGenerator(otherGqGroup)
					.genRandomCiphertextVector(numCiphertexts, ciphertextLength);
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroKnowledgeProofservice.verifyDecryptions(otherCiphertexts, publicKey, verifiableDecryptions, auxiliaryInformation));
			assertEquals("The verifiable decryptions must have the same group as the ciphertexts.", exception.getMessage());
		}

		@Test
		@DisplayName("Verifying decryptions with public key from different group throws an IllegalArgumentException")
		void verifyDecryptionsWithOtherPublicKey() {
			final ElGamalMultiRecipientPublicKey otherPublicKey = new ElGamalGenerator(otherGqGroup).genRandomPublicKey(keyLength);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroKnowledgeProofservice.verifyDecryptions(ciphertexts, otherPublicKey, verifiableDecryptions, auxiliaryInformation));
			assertEquals("The public key must have the same group as the ciphertexts.", exception.getMessage());
		}

		@Test
		@DisplayName("Verifying decryptions with a different number of ciphertexts throws an IllegalArgumentException")
		void verifyDecryptionsWithDifferentNumberCiphertexts() {
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> otherCiphertexts = elGamalGenerator
					.genRandomCiphertextVector(numCiphertexts, ciphertextLength + 1);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroKnowledgeProofservice.verifyDecryptions(otherCiphertexts, publicKey, verifiableDecryptions, auxiliaryInformation));
			assertEquals("The verifiable decryptions must have the same size l as the ciphertexts.", exception.getMessage());
		}

		@Test
		@DisplayName("Verifying decryptions with a different number of public key elements throws an IllegalArgumentException")
		void verifyDecryptionsWithDifferentNumberPublicKeyElements() {
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> otherCiphertexts = elGamalGenerator
					.genRandomCiphertextVector(numCiphertexts, keyLength + 1);
			final ElGamalMultiRecipientKeyPair otherKeyPair = elGamal.genKeyPair(gqGroup, keyLength + 1, randomService);
			final VerifiableDecryptions otherVerifiableDecryptions = zeroKnowledgeProofservice
					.genVerifiableDecryptions(otherCiphertexts, otherKeyPair, auxiliaryInformation);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroKnowledgeProofservice.verifyDecryptions(otherCiphertexts, publicKey, otherVerifiableDecryptions, auxiliaryInformation));
			assertEquals("The ciphertexts must have at most as many elements as the public key.", exception.getMessage());
		}

		@Test
		@DisplayName("Verifying decryptions with empty ciphertexts vector throws an IllegalArgumentException")
		void verifyDecryptionsWithEmptyCiphertexts() {
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> otherCiphertexts = elGamalGenerator
					.genRandomCiphertextVector(0, ciphertextLength);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroKnowledgeProofservice.verifyDecryptions(otherCiphertexts, publicKey, verifiableDecryptions, auxiliaryInformation));
			assertEquals("There must be at least one ciphertext.", exception.getMessage());
		}

		@Test
		@DisplayName("Verifying decryptions with ciphertexts of different lengths throws an IllegalArgumentException")
		void verifyDecryptionsWithDifferentLengthCiphertexts() {
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> otherCiphertexts = elGamalGenerator
					.genRandomCiphertextVector(numCiphertexts + 1, ciphertextLength);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroKnowledgeProofservice.verifyDecryptions(otherCiphertexts, publicKey, verifiableDecryptions, auxiliaryInformation));
			assertEquals("There must be as many verifiable decryptions as ciphertexts.", exception.getMessage());
		}

		@Test
		@DisplayName("Verifying decryptions with ciphertexts without elements throws an IllegalArgumentException")
		void verifyDecryptionsWithNoCiphertextElements() {
			final ElGamalMultiRecipientCiphertext noElementCiphertext = mock(ElGamalMultiRecipientCiphertext.class);
			when(noElementCiphertext.size()).thenReturn(0);
			when(noElementCiphertext.getGroup()).thenReturn(gqGroup);
			final DecryptionProof otherDecryptionProof = mock(DecryptionProof.class);
			when(otherDecryptionProof.size()).thenReturn(0);
			when(otherDecryptionProof.getGroup()).thenReturn(zqGroup);

			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> otherCiphertexts = GroupVector.of(noElementCiphertext);
			final VerifiableDecryptions otherVerifiableDecryptions = new VerifiableDecryptions(GroupVector.of(noElementCiphertext),
					GroupVector.of(otherDecryptionProof));
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroKnowledgeProofservice.verifyDecryptions(otherCiphertexts, publicKey, otherVerifiableDecryptions, auxiliaryInformation));
			assertEquals("The ciphertexts must have at least 1 element.", exception.getMessage());
		}
	}
}
