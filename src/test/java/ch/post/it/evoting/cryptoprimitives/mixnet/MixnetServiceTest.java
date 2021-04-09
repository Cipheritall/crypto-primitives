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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;

class MixnetServiceTest extends TestGroupSetup {

	private static ElGamalMultiRecipientPublicKey publicKey;
	private static int keySize;

	@BeforeEach
	void setUpAll() {
		keySize = secureRandom.nextInt(10) + 1;
		publicKey = new ElGamalGenerator(gqGroup).genRandomPublicKey(keySize);
	}

	@Test
	void testMixnetCreationWithNullHashServiceThrows(){
		assertThrows(NullPointerException.class, () -> new MixnetService(null));
	}

	@Test
	void testNullChecking() {
		HashService hashService = mock(HashService.class);
		Mixnet mixnet = new MixnetService(hashService);

		List<ElGamalMultiRecipientCiphertext> inputCiphertextList = new ElGamalGenerator(gqGroup).genRandomCiphertextVector(5, 5);
		assertThrows(NullPointerException.class, () -> mixnet.genVerifiableShuffle(null, publicKey));
		assertThrows(NullPointerException.class, () -> mixnet.genVerifiableShuffle(inputCiphertextList, null));
	}

	@Test
	void testMultipleCipherTextsCheck() {
		HashService hashService = mock(HashService.class);
		Mixnet mixnet = new MixnetService(hashService);

		ElGamalMultiRecipientCiphertext cipherText = mock(ElGamalMultiRecipientCiphertext.class);
		List<ElGamalMultiRecipientCiphertext> inputCiphertextList = Collections.singletonList(cipherText);

		List<ElGamalMultiRecipientCiphertext> emptyCiphertextList = new ArrayList<>();
		IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> mixnet.genVerifiableShuffle(emptyCiphertextList, publicKey));
		assertEquals("N must be >= 2", illegalArgumentException.getMessage());

		illegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> mixnet.genVerifiableShuffle(inputCiphertextList, publicKey));
		assertEquals("N must be >= 2", illegalArgumentException.getMessage());
	}

	@Test
	void testNumberOfCiphertextsTooLargeThrows() {
		HashService hashService = mock(HashService.class);
		Mixnet mixnet = new MixnetService(hashService);

		int maxNumberCiphertexts = gqGroup.getQ().intValueExact() + 3;
		int Nc =  maxNumberCiphertexts + 1;
		int l = keySize;
		List<ElGamalMultiRecipientCiphertext> ciphertexts = new ElGamalGenerator(gqGroup).genRandomCiphertextVector(Nc, l);

		IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> mixnet.genVerifiableShuffle(ciphertexts, publicKey));
		assertEquals("N must be smaller or equal to q - 3", illegalArgumentException.getMessage());
	}

	@Test
	void testSameGroup() {
		HashService hashService = mock(HashService.class);
		Mixnet mixnet = new MixnetService(hashService);

		ElGamalGenerator elGamalGenerator = new ElGamalGenerator(otherGqGroup);
		List<ElGamalMultiRecipientCiphertext> inputCiphertextList = elGamalGenerator.genRandomCiphertextVector(2, 2);

		IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> mixnet.genVerifiableShuffle(inputCiphertextList, publicKey));
		assertEquals("Ciphertexts must have the same group as the publicKey", illegalArgumentException.getMessage());
	}

	@Test
	void testValidShuffle() throws NoSuchAlgorithmException {
		GqGroup group = GroupTestData.getGroupP59();

		publicKey = new ElGamalGenerator(group).genRandomPublicKey(keySize);

		HashService hashService = mock(HashService.class);
		Mixnet mixnet = new MixnetService(hashService);
		when(hashService.recursiveHash(any())).thenReturn(new byte[] { 0b10 });

		int Nc = secureRandom.nextInt(10) + 2;
		int l = secureRandom.nextInt(keySize) + 1;
		ElGamalGenerator elGamalGenerator = new ElGamalGenerator(group);
		List<ElGamalMultiRecipientCiphertext> inputCiphertextList = elGamalGenerator.genRandomCiphertextVector(Nc, l);

		VerifiableShuffle verifiableShuffle = mixnet.genVerifiableShuffle(inputCiphertextList, publicKey);

		assertNotNull(verifiableShuffle);
		assertNotNull(verifiableShuffle.getShuffleArgument());
		assertEquals(inputCiphertextList.size(), verifiableShuffle.getShuffledCiphertextList().size());

	}

	@Test
	void testSizeOfCiphertextsGreaterThanPublicKeySize() {
		HashService hashService = mock(HashService.class);
		Mixnet mixnet = new MixnetService(hashService);

		when(hashService.recursiveHash(any())).thenReturn(new byte[] { 0b10 });

		int Nc = secureRandom.nextInt(gqGroup.getQ().intValueExact() - 4) + 2;
		int l = keySize + 1;
		ElGamalGenerator elGamalGenerator = new ElGamalGenerator(gqGroup);
		List<ElGamalMultiRecipientCiphertext> inputCiphertextList = elGamalGenerator.genRandomCiphertextVector(Nc, l);

		IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> mixnet.genVerifiableShuffle(inputCiphertextList, publicKey));

		assertEquals("Ciphertexts must not contain more elements than the publicKey", illegalArgumentException.getMessage());

	}
}
