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

import static ch.post.it.evoting.cryptoprimitives.GroupVector.toGroupVector;
import static java.util.stream.Collectors.toList;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedStatic;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.SecurityLevelConfig;
import ch.post.it.evoting.cryptoprimitives.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.VerificationResult;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientKeyPair;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientMessage;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPrivateKey;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.hashing.TestHashService;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.Generators;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.JsonData;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.TestParameters;

class DecryptionProofServiceTest extends TestGroupSetup {

	private static final SecureRandom random = new SecureRandom();
	private static final RandomService randomService = new RandomService();
	private static final List<String> auxiliaryInformation = Arrays.asList("aux", "1");

	private static ElGamalGenerator elGamalGenerator;
	private static DecryptionProofService decryptionProofService;

	@BeforeAll
	static void setupAll() {
		elGamalGenerator = new ElGamalGenerator(gqGroup);

		HashService hashService = TestHashService.create(gqGroup.getQ());
		decryptionProofService = new DecryptionProofService(randomService, hashService);
	}

	private static class TestValues {
		// Create groups
		private final BigInteger p = BigInteger.valueOf(23);
		private final BigInteger q = BigInteger.valueOf(11);
		private final BigInteger g = BigInteger.valueOf(2);
		private final GqGroup gqGroup = new GqGroup(p, q, g);
		private final ZqGroup zqGroup = new ZqGroup(q);

		// Create BigIntegers
		private final BigInteger TWO = BigInteger.valueOf(2);
		private final BigInteger THREE = BigInteger.valueOf(3);
		private final BigInteger FOUR = BigInteger.valueOf(4);
		private final BigInteger FIVE = BigInteger.valueOf(5);
		private final BigInteger SIX = BigInteger.valueOf(6);
		private final BigInteger SEVEN = BigInteger.valueOf(7);
		private final BigInteger EIGHT = BigInteger.valueOf(8);
		private final BigInteger TEN = BigInteger.TEN;

		// Create GqElements
		private final GqElement gThree = GqElement.create(THREE, gqGroup);
		private final GqElement gFour = GqElement.create(FOUR, gqGroup);
		private final GqElement gEight = GqElement.create(EIGHT, gqGroup);
		private final GqElement gThirteen = GqElement.create(BigInteger.valueOf(13), gqGroup);

		// Create ZqElements
		private final ZqElement zTwo = ZqElement.create(TWO, zqGroup);
		private final ZqElement zThree = ZqElement.create(THREE, zqGroup);
		private final ZqElement zFive = ZqElement.create(FIVE, zqGroup);
		private final ZqElement zSix = ZqElement.create(SIX, zqGroup);
		private final ZqElement zSeven = ZqElement.create(SEVEN, zqGroup);
		private final ZqElement zEight = ZqElement.create(EIGHT, zqGroup);
		private final ZqElement zTen = ZqElement.create(TEN, zqGroup);

		// Create input arguments
		// c = {9, (18, 9, 13)}
		// sk = (3, 7, 2)
		// pk = (8, 13, 4)
		// m = (4, 8, 3)
		// iAux = "Auxiliary Data"
		private final ElGamalMultiRecipientMessage m = new ElGamalMultiRecipientMessage(Arrays.asList(gFour, gEight, gThree));
		private final ElGamalMultiRecipientPublicKey pk = new ElGamalMultiRecipientPublicKey(Arrays.asList(gEight, gThirteen, gFour));
		private final ElGamalMultiRecipientPrivateKey sk = new ElGamalMultiRecipientPrivateKey(Arrays.asList(zThree, zSeven, zTwo));
		private final ElGamalMultiRecipientCiphertext c = ElGamalMultiRecipientCiphertext.getCiphertext(m, zFive, pk);
		private final List<String> iAux = Collections.singletonList("Auxiliary Data");

		private final List<BigInteger> randomValues = Arrays.asList(FOUR, SEVEN, FIVE);

		// Create output arguments
		private final ZqElement e = zEight;
		private final GroupVector<ZqElement, ZqGroup> z = GroupVector.of(zSix, zEight, zTen);

		private ElGamalMultiRecipientKeyPair createKeyPair() {
			final ElGamalMultiRecipientKeyPair keyPair = mock(ElGamalMultiRecipientKeyPair.class);
			when(keyPair.getPrivateKey()).thenReturn(sk);
			when(keyPair.getPublicKey()).thenReturn(pk);
			return keyPair;
		}

		private RandomService getSpecificRandomService() {
			return new RandomService() {
				final Iterator<BigInteger> values = randomValues.iterator();

				@Override
				public BigInteger genRandomInteger(BigInteger upperBound) {
					return values.next();
				}
			};
		}

		private DecryptionProofService createDecryptionProofService() {
			final RandomService randomService = getSpecificRandomService();
			final HashService hashService = TestHashService.create(q);
			return new DecryptionProofService(randomService, hashService);
		}

		private DecryptionProof createDecryptionProof() {
			return new DecryptionProof(e, z);
		}
	}

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

		private ElGamalMultiRecipientCiphertext ciphertext;
		private ElGamalMultiRecipientKeyPair keyPair;
		private ElGamalMultiRecipientMessage message;

		private int keyLength;
		private int messageLength;

		@BeforeEach
		void setup() {
			int maxLength = 10;
			keyLength = random.nextInt(maxLength - 1) + 2;
			messageLength = random.nextInt(keyLength) + 1;
			keyPair = ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, keyLength, randomService);
			GroupVector<GqElement, GqGroup> messageElements = gqGroupGenerator.genRandomGqElementVector(messageLength);
			message = new ElGamalMultiRecipientMessage(messageElements);
			ciphertext = ElGamalMultiRecipientCiphertext.getCiphertext(message, zqGroupGenerator.genRandomZqElementMember(), keyPair.getPublicKey());

			HashService hashService = TestHashService.create(gqGroup.getQ());
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
		@DisplayName("with hash service with too long hash length throws IllegalArgumentException")
		void genDecryptionProofWithBadHashService() {
			final DecryptionProofService badService = new DecryptionProofService(randomService, new HashService());
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> badService.genDecryptionProof(ciphertext, keyPair, message, auxiliaryInformation));
			assertEquals("The hash service's bit length must be smaller than the bit length of q.", exception.getMessage());
		}

		@Test
		@DisplayName("with a hashService that has a too long hash length throws an IllegalArgumentException")
		void genDecryptionProofWithHashServiceWithTooLongHashLength() {
			HashService otherHashService = new HashService();
			DecryptionProofService otherProofService = new DecryptionProofService(randomService, otherHashService);
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> otherProofService.genDecryptionProof(ciphertext, keyPair, message, auxiliaryInformation));
			assertEquals("The hash service's bit length must be smaller than the bit length of q.", exception.getMessage());
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
			// Create input arguments
			TestValues values = new TestValues();
			final ElGamalMultiRecipientMessage m = values.m;
			final ElGamalMultiRecipientKeyPair keyPair = values.createKeyPair();
			final ElGamalMultiRecipientCiphertext c = values.c;
			final List<String> iAux = values.iAux;

			DecryptionProofService service = values.createDecryptionProofService();

			// Create expected output
			DecryptionProof expected = values.createDecryptionProof();

			assertEquals(expected, service.genDecryptionProof(c, keyPair, m, iAux));
		}
	}

	@Nested
	@DisplayName("Verifying a decryption proof...")
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	class VerifyDecryptionTest {

		private ElGamalMultiRecipientCiphertext ciphertext;
		private ElGamalMultiRecipientPublicKey publicKey;
		private ElGamalMultiRecipientMessage message;
		private DecryptionProof decryptionProof;

		private int keyLength;
		private int messageLength;

		@BeforeEach
		void setup() {
			int maxLength = 10;
			keyLength = random.nextInt(maxLength - 1) + 1;
			messageLength = random.nextInt(keyLength) + 1;
			ElGamalMultiRecipientKeyPair keyPair = ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, keyLength, randomService);
			publicKey = keyPair.getPublicKey();
			GroupVector<GqElement, GqGroup> messageElements = gqGroupGenerator.genRandomGqElementVector(messageLength);
			message = new ElGamalMultiRecipientMessage(messageElements);
			ciphertext = ElGamalMultiRecipientCiphertext.getCiphertext(message, zqGroupGenerator.genRandomZqElementMember(), keyPair.getPublicKey());
			decryptionProof = decryptionProofService.genDecryptionProof(ciphertext, keyPair, message, auxiliaryInformation);
		}

		@Test
		@DisplayName("with null arguments throws a NullPointerException")
		void verifyDecryptionWithNullArguments() {
			assertAll(
					() -> assertThrows(NullPointerException.class,
							() -> decryptionProofService.verifyDecryption(null, publicKey, message, decryptionProof, auxiliaryInformation)),
					() -> assertThrows(NullPointerException.class,
							() -> decryptionProofService.verifyDecryption(ciphertext, null, message, decryptionProof, auxiliaryInformation)),
					() -> assertThrows(NullPointerException.class,
							() -> decryptionProofService.verifyDecryption(ciphertext, publicKey, null, decryptionProof, auxiliaryInformation)),
					() -> assertThrows(NullPointerException.class,
							() -> decryptionProofService.verifyDecryption(ciphertext, publicKey, message, null, auxiliaryInformation)),
					() -> assertThrows(NullPointerException.class,
							() -> decryptionProofService.verifyDecryption(ciphertext, publicKey, message, decryptionProof, null))
			);
		}

		@Test
		@DisplayName("with valid input and non empty auxiliary information returns true")
		void verifyDecryptionWithValidInput() {
			assertTrue(decryptionProofService.verifyDecryption(ciphertext, publicKey, message, decryptionProof, auxiliaryInformation).verify()
					.isVerified());
		}

		@Test
		@DisplayName("with hash service with too long hash length throws IllegalArgumentException")
		void verifyDecryptionWithBadHashService() {
			final DecryptionProofService badService = new DecryptionProofService(randomService, new HashService());
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> badService.verifyDecryption(ciphertext, publicKey, message, decryptionProof, auxiliaryInformation));
			assertEquals("The hash service's bit length must be smaller than the bit length of q.", exception.getMessage());
		}

		@Test
		@DisplayName("with valid input and empty auxiliary information returns true")
		void verifyDecryptionWithValidInputNoAux() {
			ElGamalMultiRecipientKeyPair keyPair = ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, keyLength, randomService);
			publicKey = keyPair.getPublicKey();
			GroupVector<GqElement, GqGroup> messageElements = gqGroupGenerator.genRandomGqElementVector(messageLength);
			message = new ElGamalMultiRecipientMessage(messageElements);
			ciphertext = ElGamalMultiRecipientCiphertext.getCiphertext(message, zqGroupGenerator.genRandomZqElementMember(), keyPair.getPublicKey());
			decryptionProof = decryptionProofService.genDecryptionProof(ciphertext, keyPair, message, Collections.emptyList());
			assertTrue(decryptionProofService.verifyDecryption(ciphertext, publicKey, message, decryptionProof, Collections.emptyList()).verify()
					.isVerified());
		}

		@Test
		@DisplayName("with the ciphertext from a different group throws an IllegalArgumentException")
		void verifyDecryptionWithCiphertextFromDifferentGroup() {
			ciphertext = new ElGamalGenerator(otherGqGroup).genRandomCiphertext(messageLength);
			IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> decryptionProofService.verifyDecryption(ciphertext, publicKey, message, decryptionProof, auxiliaryInformation));
			assertEquals("The ciphertext, the public key and the message must have the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("with the public key from a different group throws an IllegalArgumentException")
		void verifyDecryptionWithPublicKeyFromDifferentGroup() {
			publicKey = ElGamalMultiRecipientKeyPair.genKeyPair(otherGqGroup, keyLength, randomService).getPublicKey();
			IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> decryptionProofService.verifyDecryption(ciphertext, publicKey, message, decryptionProof, auxiliaryInformation));
			assertEquals("The ciphertext, the public key and the message must have the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("with the message from a different group throws an IllegalArgumentException")
		void verifyDecryptionWithMessageFromDifferentGroup() {
			message = new ElGamalGenerator(otherGqGroup).genRandomMessage(messageLength);
			IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> decryptionProofService.verifyDecryption(ciphertext, publicKey, message, decryptionProof, auxiliaryInformation));
			assertEquals("The ciphertext, the public key and the message must have the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("with the decryption proof from a different group throws an IllegalArgumentException")
		void verifyDecryptionWithDecryptionProofFromDifferentGroup() {
			decryptionProof = new DecryptionProof(otherZqGroupGenerator.genRandomZqElementMember(),
					otherZqGroupGenerator.genRandomZqElementVector(messageLength));
			IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> decryptionProofService.verifyDecryption(ciphertext, publicKey, message, decryptionProof, auxiliaryInformation));
			assertEquals("The decryption proof must have the same group order as the ciphertext, the message and the public key.",
					exception.getMessage());
		}

		@Test
		@DisplayName("with the ciphertext of a different size throws an IllegalArgumentException")
		void verifyDecryptionWithCiphertextOfDifferentSize() {
			ciphertext = elGamalGenerator.genRandomCiphertext(messageLength + 1);
			IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> decryptionProofService.verifyDecryption(ciphertext, publicKey, message, decryptionProof, auxiliaryInformation));
			assertEquals("The ciphertext, the message and the decryption proof must have the same size.", exception.getMessage());
		}

		@Test
		@DisplayName("with a too long ciphertext and message throws an IllegalArgumentException")
		void verifyDecryptionWithTooShortPublicKey() {
			ciphertext = elGamalGenerator.genRandomCiphertext(keyLength + 1);
			message = elGamalGenerator.genRandomMessage(keyLength + 1);
			decryptionProof = new DecryptionProof(zqGroupGenerator.genRandomZqElementMember(),
					zqGroupGenerator.genRandomZqElementVector(keyLength + 1));
			IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> decryptionProofService.verifyDecryption(ciphertext, publicKey, message, decryptionProof, auxiliaryInformation));
			assertEquals("The ciphertext, the message and the decryption proof must be smaller than or equal to the public key.",
					exception.getMessage());
		}

		@Test
		@DisplayName("with a too short z in the decryption proof throws an IllegalArgumentException")
		void verifyDecryptionWithTooShortDecryptionProofZ() {
			decryptionProof = new DecryptionProof(zqGroupGenerator.genRandomZqElementMember(),
					zqGroupGenerator.genRandomZqElementVector(messageLength + 1));
			IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> decryptionProofService.verifyDecryption(ciphertext, publicKey, message, decryptionProof, auxiliaryInformation));
			assertEquals("The ciphertext, the message and the decryption proof must have the same size.", exception.getMessage());
		}

		@Test
		@DisplayName("with another ciphertext returns false")
		void verifyDecryptionWithOtherCiphertext() {
			TestValues values = new TestValues();
			final ElGamalMultiRecipientMessage m = values.m;
			final ElGamalMultiRecipientKeyPair keyPair = values.createKeyPair();
			final ElGamalMultiRecipientCiphertext c = values.c;
			final List<String> iAux = values.iAux;

			final DecryptionProofService service1 = values.createDecryptionProofService();
			final DecryptionProofService service2 = values.createDecryptionProofService();

			// Create expected output
			final DecryptionProof proof1 = service1.genDecryptionProof(c, keyPair, m, iAux);
			final DecryptionProof proof2 = service2.genDecryptionProof(c, keyPair, m, Collections.emptyList());

			final ElGamalMultiRecipientCiphertext cPrime = ElGamalMultiRecipientCiphertext.create(values.gEight, c.getPhi());

			final VerificationResult result1 = service1.verifyDecryption(cPrime, keyPair.getPublicKey(), m, proof1, iAux).verify();
			final VerificationResult result2 = service1.verifyDecryption(cPrime, keyPair.getPublicKey(), m, proof2, Collections.emptyList()).verify();

			assertFalse(result1.isVerified());
			assertFalse(result2.isVerified());

			assertEquals(String.format("Could not verify decryption proof of ciphertext %s.", cPrime), result1.getErrorMessages().getFirst());
			assertEquals(String.format("Could not verify decryption proof of ciphertext %s.", cPrime), result2.getErrorMessages().getFirst());
		}

		@Test
		@DisplayName("with another public key returns false")
		void verifyDecryptionWithOtherPublicKey() {
			TestValues values = new TestValues();
			final ElGamalMultiRecipientMessage m = values.m;
			final ElGamalMultiRecipientKeyPair keyPair = values.createKeyPair();
			final ElGamalMultiRecipientCiphertext c = values.c;
			final List<String> iAux = values.iAux;

			final DecryptionProofService service1 = values.createDecryptionProofService();
			final DecryptionProofService service2 = values.createDecryptionProofService();

			// Create expected output
			final DecryptionProof proof1 = service1.genDecryptionProof(c, keyPair, m, iAux);
			final DecryptionProof proof2 = service2.genDecryptionProof(c, keyPair, m, Collections.emptyList());

			final ElGamalMultiRecipientPublicKey pkPrime = new ElGamalMultiRecipientPublicKey(
					Arrays.asList(values.gEight, values.gEight, values.gFour));

			assertFalse(service1.verifyDecryption(c, pkPrime, m, proof1, iAux).verify().isVerified());
			assertFalse(service2.verifyDecryption(c, pkPrime, m, proof2, Collections.emptyList()).verify().isVerified());

			final VerificationResult result1 = service1.verifyDecryption(c, pkPrime, m, proof1, iAux).verify();
			final VerificationResult result2 = service1.verifyDecryption(c, pkPrime, m, proof2, Collections.emptyList()).verify();

			assertFalse(result1.isVerified());
			assertFalse(result2.isVerified());

			assertEquals(String.format("Could not verify decryption proof of ciphertext %s.", c), result1.getErrorMessages().getFirst());
			assertEquals(String.format("Could not verify decryption proof of ciphertext %s.", c), result2.getErrorMessages().getFirst());
		}

		@Test
		@DisplayName("with another message returns false")
		void verifyDecryptionWithOtherMessage() {
			TestValues values = new TestValues();
			final ElGamalMultiRecipientMessage m = values.m;
			final ElGamalMultiRecipientKeyPair keyPair = values.createKeyPair();
			final ElGamalMultiRecipientCiphertext c = values.c;
			final List<String> iAux = values.iAux;

			final DecryptionProofService service1 = values.createDecryptionProofService();
			final DecryptionProofService service2 = values.createDecryptionProofService();

			// Create expected output
			final DecryptionProof proof1 = service1.genDecryptionProof(c, keyPair, m, iAux);
			final DecryptionProof proof2 = service2.genDecryptionProof(c, keyPair, m, Collections.emptyList());

			final ElGamalMultiRecipientMessage mPrime = new ElGamalMultiRecipientMessage(Arrays.asList(values.gEight, values.gEight, values.gThree));

			final VerificationResult result1 = service1.verifyDecryption(c, keyPair.getPublicKey(), mPrime, proof1, iAux).verify();
			final VerificationResult result2 = service1.verifyDecryption(c, keyPair.getPublicKey(), mPrime, proof2, Collections.emptyList()).verify();

			assertFalse(result1.isVerified());
			assertFalse(result2.isVerified());

			assertEquals(String.format("Could not verify decryption proof of ciphertext %s.", c), result1.getErrorMessages().getFirst());
			assertEquals(String.format("Could not verify decryption proof of ciphertext %s.", c), result2.getErrorMessages().getFirst());
		}

		@Test
		@DisplayName("with another auxiliary information returns false")
		void verifyDecryptionWithOtherAuxiliaryInformation() {
			TestValues values = new TestValues();
			final ElGamalMultiRecipientMessage m = values.m;
			final ElGamalMultiRecipientKeyPair keyPair = values.createKeyPair();
			final ElGamalMultiRecipientCiphertext c = values.c;
			final List<String> iAux = values.iAux;

			final DecryptionProofService service1 = values.createDecryptionProofService();
			final DecryptionProofService service2 = values.createDecryptionProofService();

			// Create expected output
			final DecryptionProof proof1 = service1.genDecryptionProof(c, keyPair, m, iAux);
			final DecryptionProof proof2 = service2.genDecryptionProof(c, keyPair, m, Collections.emptyList());

			final List<String> iAuxPrime = new ArrayList<>(iAux);
			iAuxPrime.add("primes");

			final VerificationResult result1 = service1.verifyDecryption(c, keyPair.getPublicKey(), m, proof1, iAuxPrime).verify();
			final VerificationResult result2 = service1.verifyDecryption(c, keyPair.getPublicKey(), m, proof2, iAuxPrime).verify();

			assertFalse(result1.isVerified());
			assertFalse(result2.isVerified());

			assertEquals(String.format("Could not verify decryption proof of ciphertext %s.", c), result1.getErrorMessages().getFirst());
			assertEquals(String.format("Could not verify decryption proof of ciphertext %s.", c), result2.getErrorMessages().getFirst());
		}

		private Stream<Arguments> jsonFileArgumentProvider() {
			final List<TestParameters> parametersList = TestParameters.fromResource("/zeroknowledgeproofs/verify-decryption.json");

			return parametersList.stream().parallel().map(testParameters -> {
				// Context.
				final JsonData context = testParameters.getContext();
				final BigInteger p = context.get("p", BigInteger.class);
				final BigInteger q = context.get("q", BigInteger.class);
				final BigInteger g = context.get("g", BigInteger.class);

				try (MockedStatic<SecurityLevelConfig> mockedSecurityLevel = mockStatic(SecurityLevelConfig.class)) {
					mockedSecurityLevel.when(SecurityLevelConfig::getSystemSecurityLevel).thenReturn(testParameters.getSecurityLevel());
					final GqGroup gqGroup = new GqGroup(p, q, g);
					final ZqGroup zqGroup = new ZqGroup(q);

					final JsonData input = testParameters.getInput();

					// Parse ciphertext parameters.
					final JsonData ciphertextData = input.getJsonData("ciphertext");

					final GqElement gamma = GqElement.create(ciphertextData.get("gamma", BigInteger.class), gqGroup);
					final BigInteger[] phisAArray = ciphertextData.get("phis", BigInteger[].class);
					final List<GqElement> phi = Arrays.stream(phisAArray).map(phiA -> GqElement.create(phiA, gqGroup)).collect(toList());
					final ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertext.create(gamma, phi);

					// Parse key pair parameters
					final BigInteger[] pkArray = input.get("public_key", BigInteger[].class);
					final List<GqElement> pkElements = Arrays.stream(pkArray).map(skA -> GqElement.create(skA, gqGroup)).collect(toList());
					final ElGamalMultiRecipientPublicKey publicKey = new ElGamalMultiRecipientPublicKey(pkElements);

					// Parse message parameters
					final BigInteger[] messageArray = input.get("message", BigInteger[].class);
					final List<GqElement> messageElements = Arrays.stream(messageArray).map(mA -> GqElement.create(mA, gqGroup)).collect(toList());
					final ElGamalMultiRecipientMessage message = new ElGamalMultiRecipientMessage(messageElements);

					// Parse decryption proof parameters
					final JsonData proof = input.getJsonData("proof");

					final ZqElement e = ZqElement.create(proof.get("e", BigInteger.class), zqGroup);

					final BigInteger[] zArray = proof.get("z", BigInteger[].class);
					final GroupVector<ZqElement, ZqGroup> z = Arrays.stream(zArray)
							.map(zA -> ZqElement.create(zA, zqGroup))
							.collect(toGroupVector());
					final DecryptionProof decryptionProof = new DecryptionProof(e, z);

					// Parse auxiliary information parameters
					final String[] auxInformation = input.get("additional_information", String[].class);
					final List<String> auxiliaryInformation = Arrays.asList(auxInformation);

					// Parse output parameters
					final JsonData output = testParameters.getOutput();

					final Boolean result = output.get("verif_result", Boolean.class);

					return Arguments
							.of(ciphertext, publicKey, message, decryptionProof, auxiliaryInformation, result, testParameters.getDescription());
				}
			});
		}

		@ParameterizedTest()
		@MethodSource("jsonFileArgumentProvider")
		@DisplayName("with real values gives expected result")
		void verifyDecryptionProofWithRealValues(final ElGamalMultiRecipientCiphertext ciphertext, final ElGamalMultiRecipientPublicKey publicKey,
				final ElGamalMultiRecipientMessage message, final DecryptionProof decryptionProof, final List<String> auxiliaryInformation,
				final boolean expected, final String description) {
			final DecryptionProofService decryptionProofService = new DecryptionProofService(randomService, new HashService());
			final boolean actual = assertDoesNotThrow(
					() -> decryptionProofService.verifyDecryption(ciphertext, publicKey, message, decryptionProof, auxiliaryInformation).verify()
							.isVerified());
			assertEquals(expected, actual, String.format("assertion failed for: %s", description));
		}
	}
}
