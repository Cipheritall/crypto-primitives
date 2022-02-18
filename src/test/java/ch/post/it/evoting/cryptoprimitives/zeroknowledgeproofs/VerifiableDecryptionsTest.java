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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.SecureRandom;
import java.util.stream.IntStream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;

class VerifiableDecryptionsTest extends TestGroupSetup {

	private static final SecureRandom random = new SecureRandom();
	private static final int MAX_NUMBER_CIPHERTEXTS = 10;
	private static final int MAX_CIPHERTEXT_LENGTH = 5;

	private int numCiphertexts;
	private int numPhis;
	private ElGamalGenerator elGamalGenerator;
	private GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts;
	private GroupVector<DecryptionProof, ZqGroup> decryptionProofs;

	@BeforeEach
	void setup() {
		numCiphertexts = random.nextInt(MAX_NUMBER_CIPHERTEXTS) + 1;
		numPhis = random.nextInt(MAX_CIPHERTEXT_LENGTH) + 1;
		elGamalGenerator = new ElGamalGenerator(gqGroup);
		ciphertexts = elGamalGenerator.genRandomCiphertextVector(numCiphertexts, numPhis);
		decryptionProofs = IntStream.range(0, numCiphertexts)
				.mapToObj(i -> {
					ZqElement e = zqGroupGenerator.genRandomZqElementMember();
					GroupVector<ZqElement, ZqGroup> z = zqGroupGenerator.genRandomZqElementVector(numPhis);
					return new DecryptionProof(e, z);
				}).collect(GroupVector.toGroupVector());
	}

	@Test
	@DisplayName("Constructing a VerifiableDecryptions with null arguments throws a NullPointerException")
	void constructVerifiableDecryptionsWithNullArguments() {
		assertThrows(NullPointerException.class, () -> new VerifiableDecryptions(ciphertexts, null));
		assertThrows(NullPointerException.class, () -> new VerifiableDecryptions(null, decryptionProofs));
	}

	@Test
	@DisplayName("Constructing a VerifiableDecryptions with an empty vector of ciphertexts throws an IllegalArgumentException")
	void constructVerifiableDecryptionsWithEmptyCiphertextVector() {
		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> emptyCiphertextsVector = GroupVector.of();
		final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> new VerifiableDecryptions(emptyCiphertextsVector, decryptionProofs));
		assertEquals("There must be at least 1 ciphertext.", illegalArgumentException.getMessage());
	}

	@Test
	@DisplayName("Constructing a VerifiableDecryptions with different number of DecryptionProofs throws an IllegalArgumentException")
	void constructVerifiableDecryptionsWithCiphertextVectorDifferentSizeThanDecryptionProofList() {
		ciphertexts = elGamalGenerator.genRandomCiphertextVector(numCiphertexts + 1, numPhis);

		final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> new VerifiableDecryptions(ciphertexts, decryptionProofs));
		assertEquals("Each ciphertext must have exactly one decryption proof.", illegalArgumentException.getMessage());
	}

	@Test
	@DisplayName("Constructing a VerifiableDecryptions with different elements size throws an IllegalArgumentException")
	void constructVerifiableDecryptionsDifferentElementsSize() {
		ciphertexts = elGamalGenerator.genRandomCiphertextVector(numCiphertexts, numPhis + 1);

		final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> new VerifiableDecryptions(ciphertexts, decryptionProofs));
		assertEquals("The ciphertexts and decryption proofs elements must have the same size.", illegalArgumentException.getMessage());
	}

	@Test
	@DisplayName("Constructing a VerifiableDecryptions with DecryptionProofs from group of different order throws an IllegalArgumentException")
	void constructVerifiableDecryptionsWithCiphertextVectorDifferentGroupOrderThanDecryptionProofList() {
		ciphertexts = new ElGamalGenerator(otherGqGroup).genRandomCiphertextVector(numCiphertexts, numPhis);

		final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> new VerifiableDecryptions(ciphertexts, decryptionProofs));
		assertEquals("The ciphertexts and decryption proofs must have groups of the same order.", illegalArgumentException.getMessage());
	}
}
