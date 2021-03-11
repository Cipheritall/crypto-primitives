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
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;

class MixnetServiceTest {

	@Test
	void testNullChecking() {
		HashService hashService = mock(HashService.class);
		Mixnet mixnet = new MixnetService(hashService);

		List<ElGamalMultiRecipientCiphertext> inputCiphertextList = new ArrayList<>();

		ElGamalMultiRecipientPublicKey mixingPublicKey = mock(ElGamalMultiRecipientPublicKey.class);
		assertThrows(NullPointerException.class, () -> mixnet.genVerifiableShuffle(inputCiphertextList, null));
		assertThrows(NullPointerException.class, () -> mixnet.genVerifiableShuffle(null, mixingPublicKey));
	}

	@Test
	void testMultipleCipherTextsCheck() {
		HashService hashService = mock(HashService.class);
		Mixnet mixnet = new MixnetService(hashService);
		List<ElGamalMultiRecipientCiphertext> inputCiphertextList = new ArrayList<>();
		ElGamalMultiRecipientCiphertext cipherText = mock(ElGamalMultiRecipientCiphertext.class);
		inputCiphertextList.add(cipherText);

		ElGamalMultiRecipientPublicKey mixingPublicKey = mock(ElGamalMultiRecipientPublicKey.class);

		List<ElGamalMultiRecipientCiphertext> emptyCiphertextList = new ArrayList<>();
		IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> mixnet.genVerifiableShuffle(emptyCiphertextList, mixingPublicKey));
		assertEquals("N must be >= 2", illegalArgumentException.getMessage());

		illegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> mixnet.genVerifiableShuffle(inputCiphertextList, mixingPublicKey));
		assertEquals("N must be >= 2", illegalArgumentException.getMessage());
	}

	@Test
	void testSameGroup() {

		HashService hashService = mock(HashService.class);
		Mixnet mixnet = new MixnetService(hashService);

		GqGroup group = GroupTestData.getGqGroup();
		ElGamalGenerator elGamalGenerator = new ElGamalGenerator(group);
		List<ElGamalMultiRecipientCiphertext> inputCiphertextList = elGamalGenerator.genRandomCiphertextVector(3, 3);

		ElGamalMultiRecipientPublicKey mixingPublicKey = mock(ElGamalMultiRecipientPublicKey.class, RETURNS_DEEP_STUBS);
		when(mixingPublicKey.getGroup()).thenReturn(GroupTestData.getDifferentGqGroup(group));

		IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> mixnet.genVerifiableShuffle(inputCiphertextList, mixingPublicKey));
		assertEquals("InputCiphertextList must have the same group as publicKey", illegalArgumentException.getMessage());
	}

	@Test
	void testValidShuffle() throws NoSuchAlgorithmException {
		HashService hashService = mock(HashService.class);
		Mixnet mixnet = new MixnetService(hashService);

		when(hashService.recursiveHash(any())).thenReturn(new byte[] { 0b10 });

		GqGroup group = GroupTestData.getGroupP59();
		ElGamalGenerator elGamalGenerator = new ElGamalGenerator(group);
		List<ElGamalMultiRecipientCiphertext> inputCiphertextList = elGamalGenerator.genRandomCiphertextVector(3, 3);
		ElGamalMultiRecipientPublicKey mixingPublicKey = elGamalGenerator.genRandomPublicKey(3);

		VerifiableShuffle verifiableShuffle = mixnet.genVerifiableShuffle(inputCiphertextList, mixingPublicKey);

		assertNotNull(verifiableShuffle);
		assertNotNull(verifiableShuffle.getShuffleArgument());
		assertEquals(inputCiphertextList.size(), verifiableShuffle.getShuffledCiphertextList().size());

	}

	@Test
	void testNumberOfCipherTextsGreaterthanPublicKey() {
		HashService hashService = mock(HashService.class);
		Mixnet mixnet = new MixnetService(hashService);

		when(hashService.recursiveHash(any())).thenReturn(new byte[] { 0b10 });

		GqGroup group = GroupTestData.getGqGroup();
		ElGamalGenerator elGamalGenerator = new ElGamalGenerator(group);
		List<ElGamalMultiRecipientCiphertext> inputCiphertextList = elGamalGenerator.genRandomCiphertextVector(4, 4);
		ElGamalMultiRecipientPublicKey mixingPublicKey = elGamalGenerator.genRandomPublicKey(3);

		IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> mixnet.genVerifiableShuffle(inputCiphertextList, mixingPublicKey));

		assertEquals("The ciphertext must not contain more elements than the publicKey", illegalArgumentException.getMessage());

	}
}
