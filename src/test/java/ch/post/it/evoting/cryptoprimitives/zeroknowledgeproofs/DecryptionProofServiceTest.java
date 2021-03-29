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
package ch.post.it.evoting.cryptoprimitives.zeroknowledgeproofs;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientKeyPair;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientMessage;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPrivateKey;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.hashing.TestHashService;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.Generators;

class DecryptionProofServiceTest extends TestGroupSetup {

	@Nested
	@DisplayName("Computing a phi decryption...")
	class ComputePhiDecryptionTest {
		@Test
		@DisplayName("with null arguments throws a NullPointerException")
		void notNullChecks() {
			GroupVector<ZqElement, ZqGroup> preImage = GroupVector.of();
			GqElement gamma = gqGroupGenerator.genMember();

			assertThrows(NullPointerException.class, () -> DecryptionProofService.computePhiDecryption(preImage, null));
			assertThrows(NullPointerException.class, () -> DecryptionProofService.computePhiDecryption(null, gamma));
		}

		@Test
		@DisplayName("with the pre-image and base having different group orders throws an IllegalArgumentException")
		void checkNotSameOrder() {
			GqElement gamma = gqGroupGenerator.genMember();
			int zqGroupVectorSize = 3;
			GroupVector<ZqElement, ZqGroup> preImage = otherZqGroupGenerator.genRandomZqElementVector(zqGroupVectorSize);

			IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
					() -> DecryptionProofService.computePhiDecryption(preImage, gamma));

			assertEquals("The preImage and base should have the same group order.", illegalArgumentException.getMessage());
		}

		@RepeatedTest(10)
		@DisplayName("with valid input arguments returns an image with the correct size")
		void testPhiFunctionSizeAndCalculatingWithoutErrorOnRandomValues() {
			GqElement gamma = gqGroupGenerator.genMember();
			int zqGroupVectorSize = 3;
			GroupVector<ZqElement, ZqGroup> preImage = zqGroupGenerator.genRandomZqElementVector(zqGroupVectorSize);

			List<GqElement> phiFunction = DecryptionProofService.computePhiDecryption(preImage, gamma);

			assertEquals(2 * preImage.size(), phiFunction.size());
		}

		@Test
		@DisplayName("with specific values returns the expected result")
		void checkPhiFunctionAgainstHandCalculations() {

			GqGroup groupP59 = GroupTestData.getGroupP59();
			GqElement gamma = GqElement.create(BigInteger.valueOf(12), groupP59);

			ZqGroup zqGroup = ZqGroup.sameOrderAs(groupP59);
			ZqElement zqElement9 = ZqElement.create(BigInteger.valueOf(9), zqGroup);
			ZqElement zqElement15 = ZqElement.create(BigInteger.valueOf(15), zqGroup);
			ZqElement zqElement8 = ZqElement.create(BigInteger.valueOf(8), zqGroup);

			ImmutableList<ZqElement> preImageZqElements = ImmutableList.of(zqElement9, zqElement15, zqElement8);

			GroupVector<ZqElement, ZqGroup> preImage = GroupVector.from(preImageZqElements);

			List<GqElement> computePhiFunction = DecryptionProofService.computePhiDecryption(preImage, gamma);

			GqElement gqElement36 = GqElement.create(BigInteger.valueOf(36), groupP59);
			GqElement gqElement48 = GqElement.create(BigInteger.valueOf(48), groupP59);
			GqElement gqElement12 = GqElement.create(BigInteger.valueOf(12), groupP59);
			GqElement gqElement16 = GqElement.create(BigInteger.valueOf(16), groupP59);
			GqElement gqElement22 = GqElement.create(BigInteger.valueOf(22), groupP59);
			GqElement gqElement21 = GqElement.create(BigInteger.valueOf(21), groupP59);

			List<GqElement> phiFunction = Arrays.asList(gqElement36, gqElement48, gqElement12, gqElement16, gqElement22, gqElement21);

			assertEquals(phiFunction, computePhiFunction);
		}
	}

	@Nested
	@DisplayName("Generating a decryption proof...")
	class GenDecryptionProofTest {

		private final SecureRandom random = new SecureRandom();
		private final RandomService randomService = new RandomService();

		private ElGamalGenerator elGamalGenerator;

		private ElGamalMultiRecipientCiphertext ciphertext;
		private ElGamalMultiRecipientKeyPair keyPair;
		private ElGamalMultiRecipientMessage message;
		private List<String> auxiliaryInformation;

		private DecryptionProofService decryptionProofService;

		private int keyLength;
		private int messageLength;

		@BeforeEach
		void setup() {
			int maxLength = 10;
			keyLength = random.nextInt(maxLength - 1) + 2;
			messageLength = random.nextInt(keyLength) + 1;
			elGamalGenerator = new ElGamalGenerator(gqGroup);
			keyPair = ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, keyLength, randomService);
			GroupVector<GqElement, GqGroup> messageElements = gqGroupGenerator.genRandomGqElementVector(messageLength);
			message = new ElGamalMultiRecipientMessage(messageElements);
			ciphertext = ElGamalMultiRecipientCiphertext.getCiphertext(message, zqGroupGenerator.genRandomZqElementMember(), keyPair.getPublicKey());
			auxiliaryInformation = Arrays.asList("aux", "1");

			TestHashService hashService = TestHashService.create(gqGroup.getQ());
			decryptionProofService = new DecryptionProofService(randomService, hashService);
		}

		@Test
		@DisplayName("with null arguments throws a NullPointerException")
		void genDecryptionProofWithNullArguments() {
			assertAll(
					() -> assertThrows(NullPointerException.class,
							() -> decryptionProofService.genDecryptionProof(null, keyPair, message, auxiliaryInformation)),
					() -> assertThrows(NullPointerException.class,
							() -> decryptionProofService.genDecryptionProof(ciphertext, null, message, auxiliaryInformation)),
					() -> assertThrows(NullPointerException.class,
							() -> decryptionProofService.genDecryptionProof(ciphertext, keyPair, null, auxiliaryInformation)),
					() -> assertThrows(NullPointerException.class,
							() -> decryptionProofService.genDecryptionProof(ciphertext, keyPair, message, null))
			);
		}

		@Test
		@DisplayName("with valid arguments does not throw")
		void genDecryptionProofWithValidArguments() {
			assertDoesNotThrow(() -> decryptionProofService.genDecryptionProof(ciphertext, keyPair, message, ImmutableList.of()));
			assertDoesNotThrow(() -> decryptionProofService.genDecryptionProof(ciphertext, keyPair, message, auxiliaryInformation));
		}

		@Test
		@DisplayName("with the message being different from the decrypted ciphertext throws an IllegalArgumentException")
		void genDecryptionProofWithMessageNotFromCiphertext() {
			final ElGamalMultiRecipientMessage differentMessage = Generators
					.genWhile(() -> new ElGamalMultiRecipientMessage(gqGroupGenerator.genRandomGqElementVector(messageLength)), message::equals);
			IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> decryptionProofService.genDecryptionProof(ciphertext, keyPair, differentMessage, auxiliaryInformation));
			assertEquals("The message must be equal to the decrypted ciphertext.", exception.getMessage());
		}

		@Test
		@DisplayName("with the ciphertext longer than the secret key throws an IllegalArgumentException")
		void genDecryptionProofWithCiphertextTooLong() {
			ElGamalMultiRecipientCiphertext tooLongCiphertext = elGamalGenerator.genRandomCiphertext(keyLength + 1);
			ElGamalMultiRecipientMessage tooLongMessage = elGamalGenerator.genRandomMessage(keyLength + 1);
			IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> decryptionProofService.genDecryptionProof(tooLongCiphertext, keyPair, tooLongMessage, auxiliaryInformation));
			assertEquals("The ciphertext length cannot be greater than the secret key length.", exception.getMessage());
		}

		@Test
		@DisplayName("with the ciphertext and secret key group orders being different throws an IllegalArgumentException")
		void genDecryptionProofWithCiphertextAndSecretKeyDifferentGroupOrder() {
			ElGamalMultiRecipientKeyPair keyPair = ElGamalMultiRecipientKeyPair.genKeyPair(otherGqGroup, keyLength, randomService);
			IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> decryptionProofService.genDecryptionProof(ciphertext, keyPair, message, auxiliaryInformation));
			assertEquals("The ciphertext and the secret key group must have the same order.", exception.getMessage());
		}

		@Test
		@DisplayName("with specific values gives the expected result")
		void genDecryptionProofWithSpecificValues() {
			// Create groups
			BigInteger p = BigInteger.valueOf(23);
			BigInteger q = BigInteger.valueOf(11);
			BigInteger g = BigInteger.valueOf(2);
			GqGroup gqGroup = new GqGroup(p, q, g);
			ZqGroup zqGroup = new ZqGroup(q);

			// Create BigIntegers
			BigInteger TWO = BigInteger.valueOf(2);
			BigInteger THREE = BigInteger.valueOf(3);
			BigInteger FOUR = BigInteger.valueOf(4);
			BigInteger FIVE = BigInteger.valueOf(5);
			BigInteger SIX = BigInteger.valueOf(6);
			BigInteger SEVEN = BigInteger.valueOf(7);
			BigInteger EIGHT = BigInteger.valueOf(8);
			BigInteger TEN = BigInteger.valueOf(10);

			// Create GqElements
			GqElement gThree = GqElement.create(THREE, gqGroup);
			GqElement gFour = GqElement.create(FOUR, gqGroup);
			GqElement gEight = GqElement.create(EIGHT, gqGroup);
			GqElement gThirteen = GqElement.create(BigInteger.valueOf(13), gqGroup);

			// Create ZqElements
			ZqElement zTwo = ZqElement.create(TWO, zqGroup);
			ZqElement zThree = ZqElement.create(THREE, zqGroup);
			ZqElement zFive = ZqElement.create(FIVE, zqGroup);
			ZqElement zSix = ZqElement.create(SIX, zqGroup);
			ZqElement zSeven = ZqElement.create(SEVEN, zqGroup);
			ZqElement zEight = ZqElement.create(EIGHT, zqGroup);
			ZqElement zTen = ZqElement.create(TEN, zqGroup);

			// Create input arguments
			// c = {9, (18, 9, 13)}
			// sk = (3, 7, 2)
			// pk = (8, 13, 4)
			// m = (4, 8, 3)
			// iAux = "Auxiliary Data"
			final ElGamalMultiRecipientMessage m = new ElGamalMultiRecipientMessage(Arrays.asList(gFour, gEight, gThree));
			final ElGamalMultiRecipientKeyPair keyPair = mock(ElGamalMultiRecipientKeyPair.class);
			when(keyPair.getPrivateKey()).thenReturn(new ElGamalMultiRecipientPrivateKey(Arrays.asList(zThree, zSeven, zTwo)));
			when(keyPair.getPublicKey()).thenReturn(new ElGamalMultiRecipientPublicKey(Arrays.asList(gEight, gThirteen, gFour)));
			final ElGamalMultiRecipientCiphertext c = ElGamalMultiRecipientCiphertext.getCiphertext(m, zFive, keyPair.getPublicKey());
			final List<String> iAux = Collections.singletonList("Auxiliary Data");

			// Create service
			RandomService randomService = spy(RandomService.class);
			// b = (4, 7, 5)
			doReturn(FOUR, SEVEN, FIVE).when(randomService).genRandomInteger(q);
			TestHashService hashService = TestHashService.create(q);
			DecryptionProofService service = new DecryptionProofService(randomService, hashService);

			// Create expected output
			DecryptionProof expected = new DecryptionProof(zEight, GroupVector.of(zSix, zEight, zTen));

			assertEquals(expected, service.genDecryptionProof(c, keyPair, m, iAux));
		}
	}
}