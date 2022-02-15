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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.hashing.TestHashService;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.test.tools.TestGroupSetup;
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

	@Nested
	class GetVerifiableShuffleTest {

		@Test
		void testNullChecking() {
			final HashService hashService = mock(HashService.class);
			final Mixnet mixnet = new MixnetService(hashService);

			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> inputCiphertextList = new ElGamalGenerator(gqGroup)
					.genRandomCiphertextVector(5, 5);
			assertThrows(NullPointerException.class, () -> mixnet.genVerifiableShuffle(null, publicKey));
			assertThrows(NullPointerException.class, () -> mixnet.genVerifiableShuffle(inputCiphertextList, null));
		}

		@Test
		void testTooSmallGqGroup() {
			final MixnetService mixnetService = new MixnetService();
			final int minNumberOfVotes = 2;
			final int maxGroupCommitmentKeySize = gqGroup.getQ().intValueExact() - 3;
			final int Nc = secureRandom.nextInt(maxGroupCommitmentKeySize - minNumberOfVotes + 1) + minNumberOfVotes;
			final int l = secureRandom.nextInt(keySize) + 1;

			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts = new ElGamalGenerator(gqGroup).genRandomCiphertextVector(Nc, l);
			final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
					() -> mixnetService.genVerifiableShuffle(ciphertexts, publicKey));
			assertEquals("The hash service's bit length must be smaller than the bit length of q.", illegalArgumentException.getMessage());
		}

		@Test
		void testMultipleCipherTextsCheck() {
			final HashService hashService = mock(HashService.class);
			final Mixnet mixnet = new MixnetService(hashService);
			final ElGamalMultiRecipientCiphertext cipherText = mock(ElGamalMultiRecipientCiphertext.class);
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> inputCiphertextList = GroupVector.of(cipherText);

			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> emptyCiphertextList = GroupVector.of();
			IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
					() -> mixnet.genVerifiableShuffle(emptyCiphertextList, publicKey));
			assertEquals("N must be >= 2", illegalArgumentException.getMessage());

			illegalArgumentException = assertThrows(IllegalArgumentException.class,
					() -> mixnet.genVerifiableShuffle(inputCiphertextList, publicKey));
			assertEquals("N must be >= 2", illegalArgumentException.getMessage());
		}

		@Test
		void testNumberOfCiphertextsTooLargeThrows() {
			final HashService hashService = mock(HashService.class);
			final Mixnet mixnet = new MixnetService(hashService);

			final int maxNumberCiphertexts = gqGroup.getQ().intValueExact() + 3;
			final int Nc = maxNumberCiphertexts + 1;
			final int l = keySize;
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts = new ElGamalGenerator(gqGroup).genRandomCiphertextVector(Nc, l);

			final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
					() -> mixnet.genVerifiableShuffle(ciphertexts, publicKey));
			assertEquals("N must be smaller or equal to q - 3", illegalArgumentException.getMessage());
		}

		@Test
		void testSameGroup() {
			final HashService hashService = mock(HashService.class);
			final Mixnet mixnet = new MixnetService(hashService);

			final int minNumberOfVotes = 2;
			final int maxGroupCommitmentKeySize = otherGqGroup.getQ().intValueExact() - 3;
			final int Nc = secureRandom.nextInt(maxGroupCommitmentKeySize - minNumberOfVotes + 1) + minNumberOfVotes;
			final int l = secureRandom.nextInt(keySize) + 1;
			final ElGamalGenerator elGamalGenerator = new ElGamalGenerator(otherGqGroup);
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> inputCiphertextList = elGamalGenerator.genRandomCiphertextVector(Nc, l);

			final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
					() -> mixnet.genVerifiableShuffle(inputCiphertextList, publicKey));
			assertEquals("Ciphertexts must have the same group as the publicKey", illegalArgumentException.getMessage());
		}

		@Test
		void testValidShuffle() {
			final GqGroup group = GroupTestData.getLargeGqGroup();

			publicKey = new ElGamalGenerator(group).genRandomPublicKey(keySize);

			final HashService hashService = TestHashService.create(gqGroup.getQ());
			final Mixnet mixnet = new MixnetService(hashService);

			final int Nc = secureRandom.nextInt(10) + 2;
			final int l = secureRandom.nextInt(keySize) + 1;
			final ElGamalGenerator elGamalGenerator = new ElGamalGenerator(group);
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> inputCiphertextList = elGamalGenerator.genRandomCiphertextVector(Nc, l);

			final VerifiableShuffle verifiableShuffle = mixnet.genVerifiableShuffle(inputCiphertextList, publicKey);

			assertNotNull(verifiableShuffle);
			assertNotNull(verifiableShuffle.getShuffleArgument());
			assertEquals(inputCiphertextList.size(), verifiableShuffle.getShuffledCiphertexts().size());

		}

		@Test
		void testNumberOfCipherTextsGreaterthanPublicKey() {
			final HashService hashService = TestHashService.create(gqGroup.getQ());
			final Mixnet mixnet = new MixnetService(hashService);

			final int Nc = secureRandom.nextInt(gqGroup.getQ().intValueExact() - 4) + 2;
			final int l = keySize + 1;
			final ElGamalGenerator elGamalGenerator = new ElGamalGenerator(gqGroup);
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> inputCiphertextList = elGamalGenerator.genRandomCiphertextVector(Nc, l);

			final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
					() -> mixnet.genVerifiableShuffle(inputCiphertextList, publicKey));

			assertEquals("Ciphertexts must not contain more elements than the publicKey", illegalArgumentException.getMessage());

		}
	}

	@Nested
	class VerifyShuffleTest {

		@Test
		void testNullChecking() {
			final GqGroup gqGroup = GroupTestData.getLargeGqGroup();
			final HashService hashService = HashService.getInstance();
			final Mixnet mixnet = new MixnetService(hashService);

			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts = new ElGamalGenerator(gqGroup)
					.genRandomCiphertextVector(2, keySize);
			final ElGamalMultiRecipientPublicKey publicKey = new ElGamalGenerator(gqGroup).genRandomPublicKey(keySize);
			final VerifiableShuffle verifiableShuffle = mixnet.genVerifiableShuffle(ciphertexts, publicKey);
			final ShuffleArgument shuffleArgument = verifiableShuffle.getShuffleArgument();
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> shuffledCiphertexts = verifiableShuffle.getShuffledCiphertexts();

			assertThrows(NullPointerException.class, () -> mixnet.verifyShuffle(null, shuffledCiphertexts, shuffleArgument, publicKey));
			assertThrows(NullPointerException.class, () -> mixnet.verifyShuffle(ciphertexts, null, shuffleArgument, publicKey));
			assertThrows(NullPointerException.class, () -> mixnet.verifyShuffle(ciphertexts, shuffledCiphertexts, null, publicKey));
			assertThrows(NullPointerException.class, () -> mixnet.verifyShuffle(ciphertexts, shuffledCiphertexts, shuffleArgument, null));
		}

		@Test
		void testTooSmallGqGroup() {
			final MixnetService mixnetService = new MixnetService();
			int minNumberOfVotes = 2;
			int maxGroupCommitmentKeySize = gqGroup.getQ().intValueExact() - 3;
			int Nc = secureRandom.nextInt(maxGroupCommitmentKeySize - minNumberOfVotes + 1) + minNumberOfVotes;
			int l = secureRandom.nextInt(keySize) + 1;

			final ElGamalGenerator elGamalGenerator = new ElGamalGenerator(gqGroup);
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts = elGamalGenerator.genRandomCiphertextVector(Nc, l);
			final ShuffleArgument shuffleArgument = mock(ShuffleArgument.class);
			when(shuffleArgument.getGroup()).thenReturn(gqGroup);
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> shuffledCiphertexts = elGamalGenerator.genRandomCiphertextVector(Nc, l);
			final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
					() -> mixnetService.verifyShuffle(ciphertexts, shuffledCiphertexts, shuffleArgument, publicKey));
			assertEquals("The exclusive upper bound must have a bit length of at least 512.", illegalArgumentException.getMessage());
		}

		@Test
		void testEmptyCipherTextsCheck() {
			final HashService hashService = mock(HashService.class);
			final Mixnet mixnet = new MixnetService(hashService);

			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> emptyCiphertextList = GroupVector.of();
			final ShuffleArgument emptyShuffleArgument = mock(ShuffleArgument.class);
			when(emptyShuffleArgument.getGroup()).thenReturn(gqGroup);
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> emptyShuffledCiphertextList = GroupVector.of();
			final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
					() -> mixnet.verifyShuffle(emptyCiphertextList, emptyShuffledCiphertextList, emptyShuffleArgument, publicKey));
			assertEquals("N must be >= 2", illegalArgumentException.getMessage());
		}

		@Test
		void testOnlyOneCipherTextCheck() {
			final HashService hashService = mock(HashService.class);
			final Mixnet mixnet = new MixnetService(hashService);

			final ElGamalMultiRecipientCiphertext cipherText = mock(ElGamalMultiRecipientCiphertext.class);
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> singletonCiphertextList = GroupVector.of(cipherText);
			final ShuffleArgument singletonShuffleArgument = mock(ShuffleArgument.class);
			when(singletonShuffleArgument.getGroup()).thenReturn(gqGroup);
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> singletonShuffledCiphertextList = GroupVector.of(cipherText);

			final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
					() -> mixnet.verifyShuffle(singletonCiphertextList, singletonShuffledCiphertextList, singletonShuffleArgument, publicKey));
			assertEquals("N must be >= 2", illegalArgumentException.getMessage());
		}

		@Test
		void testNumberOfCiphertextsTooLargeThrows() {
			final HashService hashService = mock(HashService.class);
			final Mixnet mixnet = new MixnetService(hashService);

			final int maxNumberCiphertexts = gqGroup.getQ().intValueExact() + 3;
			final int Nc = maxNumberCiphertexts + 1;
			final int l = keySize;
			final ElGamalGenerator elGamalGenerator = new ElGamalGenerator(gqGroup);
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts = elGamalGenerator.genRandomCiphertextVector(Nc, l);
			final ShuffleArgument shuffleArgument = mock(ShuffleArgument.class);
			when(shuffleArgument.getGroup()).thenReturn(gqGroup);
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> shuffledCiphertexts = elGamalGenerator.genRandomCiphertextVector(Nc, l);

			final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
					() -> mixnet.verifyShuffle(ciphertexts, shuffledCiphertexts, shuffleArgument, publicKey));
			assertEquals("N must be smaller or equal to q - 3", illegalArgumentException.getMessage());
		}

		@Test
		void testCiphertextsSameGroup() {
			final HashService hashService = mock(HashService.class);
			final Mixnet mixnet = new MixnetService(hashService);

			final int minNumberOfVotes = 2;
			final int maxGroupCommitmentKeySize = gqGroup.getQ().intValueExact() - 3;
			final int Nc = secureRandom.nextInt(maxGroupCommitmentKeySize - minNumberOfVotes + 1) + minNumberOfVotes;
			final int l = secureRandom.nextInt(keySize) + 1;
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts = new ElGamalGenerator(gqGroup).genRandomCiphertextVector(Nc, l);
			final ShuffleArgument shuffleArgument = mock(ShuffleArgument.class);
			when(shuffleArgument.getGroup()).thenReturn(gqGroup);
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> shuffledCiphertexts = new ElGamalGenerator(otherGqGroup)
					.genRandomCiphertextVector(Nc, l);

			final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
					() -> mixnet.verifyShuffle(ciphertexts, shuffledCiphertexts, shuffleArgument, publicKey));
			assertEquals("The shuffled and re-encrypted ciphertexts must have the same group than the un-shuffled ciphertexts.",
					illegalArgumentException.getMessage());
		}

		@Test
		void testShuffleArgumentSameGroup() {
			final HashService hashService = mock(HashService.class);
			final Mixnet mixnet = new MixnetService(hashService);

			final int minNumberOfVotes = 2;
			final int maxGroupCommitmentKeySize = gqGroup.getQ().intValueExact() - 3;
			final int Nc = secureRandom.nextInt(maxGroupCommitmentKeySize - minNumberOfVotes + 1) + minNumberOfVotes;
			final int l = secureRandom.nextInt(keySize) + 1;
			final ElGamalGenerator elGamalGenerator = new ElGamalGenerator(gqGroup);
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts = elGamalGenerator.genRandomCiphertextVector(Nc, l);
			final ShuffleArgument shuffleArgument = mock(ShuffleArgument.class);
			when(shuffleArgument.getGroup()).thenReturn(otherGqGroup);
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> shuffledCiphertexts = elGamalGenerator.genRandomCiphertextVector(Nc, l);

			final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
					() -> mixnet.verifyShuffle(ciphertexts, shuffledCiphertexts, shuffleArgument, publicKey));
			assertEquals("The ciphertexts and the shuffle argument must have the same group.", illegalArgumentException.getMessage());
		}

		@Test
		void testPublicKeySameGroup() {
			final HashService hashService = mock(HashService.class);
			final Mixnet mixnet = new MixnetService(hashService);

			final int l = secureRandom.nextInt(keySize) + 1;
			final ElGamalGenerator elGamalGenerator = new ElGamalGenerator(otherGqGroup);
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts = elGamalGenerator.genRandomCiphertextVector(2, l);
			final ShuffleArgument shuffleArgument = mock(ShuffleArgument.class);
			when(shuffleArgument.getGroup()).thenReturn(otherGqGroup);
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> shuffledCiphertexts = elGamalGenerator.genRandomCiphertextVector(2, l);

			final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
					() -> mixnet.verifyShuffle(ciphertexts, shuffledCiphertexts, shuffleArgument, publicKey));
			assertEquals("The public key and the ciphertexts must have to the same group.", illegalArgumentException.getMessage());
		}

		@Test
		void testCiphertextVectorDimensions() {
			final HashService hashService = mock(HashService.class);
			final Mixnet mixnet = new MixnetService(hashService);

			final int minNumberOfVotes = 2;
			final int maxGroupCommitmentKeySize = gqGroup.getQ().intValueExact() - 3;
			final int Nc = secureRandom.nextInt(maxGroupCommitmentKeySize - minNumberOfVotes + 1) + minNumberOfVotes;
			final int l = secureRandom.nextInt(keySize) + 1;
			final ElGamalGenerator elGamalGenerator = new ElGamalGenerator(gqGroup);
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts = elGamalGenerator.genRandomCiphertextVector(Nc, l);
			final ShuffleArgument shuffleArgument = mock(ShuffleArgument.class);
			when(shuffleArgument.getGroup()).thenReturn(gqGroup);
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> shuffledCiphertexts = elGamalGenerator.genRandomCiphertextVector(Nc + 1, l);

			final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
					() -> mixnet.verifyShuffle(ciphertexts, shuffledCiphertexts, shuffleArgument, publicKey));
			assertEquals("There must be as many shuffled and re-encrypted ciphertexts, as un-shuffled ciphertexts.",
					illegalArgumentException.getMessage());
		}

		@Test
		void testCiphertextDimensions() {
			final HashService hashService = mock(HashService.class);
			final Mixnet mixnet = new MixnetService(hashService);

			final int minNumberOfVotes = 2;
			final int maxGroupCommitmentKeySize = gqGroup.getQ().intValueExact() - 3;
			final int Nc = secureRandom.nextInt(maxGroupCommitmentKeySize - minNumberOfVotes + 1) + minNumberOfVotes;
			final int l = secureRandom.nextInt(keySize) + 1;
			final ElGamalGenerator elGamalGenerator = new ElGamalGenerator(gqGroup);
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts = elGamalGenerator.genRandomCiphertextVector(Nc, l);
			final ShuffleArgument shuffleArgument = mock(ShuffleArgument.class);
			when(shuffleArgument.getGroup()).thenReturn(gqGroup);
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> shuffledCiphertexts = elGamalGenerator.genRandomCiphertextVector(Nc, l + 1);

			final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
					() -> mixnet.verifyShuffle(ciphertexts, shuffledCiphertexts, shuffleArgument, publicKey));
			assertEquals("All ciphertexts must have the same number of elements.", illegalArgumentException.getMessage());
		}

		@Test
		void testVerifiesCorrectlyGeneratedArgument() {
			final GqGroup gqGroup = GroupTestData.getLargeGqGroup();
			final HashService hashService = HashService.getInstance();
			final Mixnet mixnet = new MixnetService(hashService);

			final int minNumberOfVotes = 2;
			final int maxGroupCommitmentKeySize = 5;
			final int Nc = secureRandom.nextInt(maxGroupCommitmentKeySize - minNumberOfVotes + 1) + minNumberOfVotes;
			final int l = secureRandom.nextInt(keySize) + 1;

			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts = new ElGamalGenerator(gqGroup).genRandomCiphertextVector(Nc, l);
			final ElGamalMultiRecipientPublicKey publicKey = new ElGamalGenerator(gqGroup).genRandomPublicKey(keySize);
			final VerifiableShuffle verifiableShuffle = mixnet.genVerifiableShuffle(ciphertexts, publicKey);
			final ShuffleArgument shuffleArgument = verifiableShuffle.getShuffleArgument();
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> shuffledCiphertexts = verifiableShuffle.getShuffledCiphertexts();

			assertTrue(() -> mixnet.verifyShuffle(ciphertexts, shuffledCiphertexts, shuffleArgument, publicKey).isVerified());
		}
	}
}
