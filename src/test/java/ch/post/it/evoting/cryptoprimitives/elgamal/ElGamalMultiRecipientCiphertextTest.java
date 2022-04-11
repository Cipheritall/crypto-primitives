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
package ch.post.it.evoting.cryptoprimitives.elgamal;

import static ch.post.it.evoting.cryptoprimitives.math.GqElement.GqElementFactory;
import static ch.post.it.evoting.cryptoprimitives.math.GroupVector.toGroupVector;
import static java.util.stream.Collectors.collectingAndThen;
import static java.util.stream.Collectors.toList;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mockStatic;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedStatic;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupMatrix;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.securitylevel.SecurityLevelConfig;
import ch.post.it.evoting.cryptoprimitives.test.tools.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.JsonData;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.TestParameters;

@DisplayName("A ciphertext")
class ElGamalMultiRecipientCiphertextTest extends TestGroupSetup {

	private static ImmutableList<GqElement> validPhis;
	private static GqElement validGamma;
	private static ElGamalGenerator elGamalGenerator;

	private static RandomService randomService;

	@BeforeAll
	static void setUpAll() {
		elGamalGenerator = new ElGamalGenerator(gqGroup);
		randomService = new RandomService();
	}

	@BeforeEach
	void setUp() {
		// Generate valid phis.
		final GqElement ge1 = gqGroupGenerator.genMember();
		final GqElement ge2 = gqGroupGenerator.genMember();

		validPhis = ImmutableList.of(ge1, ge2);

		// Generate a valid gamma.
		do {
			validGamma = gqGroupGenerator.genNonIdentityMember();
		} while (validGamma.equals(gqGroup.getGenerator()));
	}

	@Test
	@DisplayName("contains the correct gamma and phis")
	void constructionTest() {
		final ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertext.create(validGamma, validPhis);

		List<GqElement> expected = new LinkedList<>();
		expected.add(validGamma);
		expected.addAll(validPhis);

		assertEquals(expected, ciphertext.stream().collect(toList()));
	}

	// Provides parameters for the withInvalidParameters test.
	static Stream<Arguments> createArgumentsProvider() {

		final List<GqElement> invalidPhis = Arrays.asList(GqElementFactory.fromValue(BigInteger.ONE, gqGroup), null);

		final List<GqElement> differentGroupPhis = Arrays.asList(gqGroupGenerator.genMember(), otherGqGroupGenerator.genMember());

		final GqElement otherGroupGamma = genOtherGroupGamma(otherGqGroup);

		return Stream.of(
				Arguments.of(null, validPhis, NullPointerException.class),
				Arguments.of(validGamma, null, NullPointerException.class),
				Arguments.of(validGamma, Collections.emptyList(), IllegalArgumentException.class),
				Arguments.of(validGamma, invalidPhis, IllegalArgumentException.class),
				Arguments.of(validGamma, differentGroupPhis, IllegalArgumentException.class),
				Arguments.of(otherGroupGamma, validPhis, IllegalArgumentException.class)
		);
	}

	@ParameterizedTest(name = "gamma = {0} and phis = {1} throws {2}")
	@MethodSource("createArgumentsProvider")
	@DisplayName("created with invalid parameters")
	void withInvalidParameters(final GqElement gamma, final List<GqElement> phis, final Class<? extends RuntimeException> exceptionClass) {
		assertThrows(exceptionClass, () -> ElGamalMultiRecipientCiphertext.create(gamma, phis));
	}

	@Test
	@DisplayName("has valid equals for gamma")
	void gammaEqualsTest() {
		final GqElement differentGamma = genDifferentGamma();

		final ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertext.create(validGamma, validPhis);
		final ElGamalMultiRecipientCiphertext sameCiphertext = ElGamalMultiRecipientCiphertext.create(validGamma, validPhis);
		final ElGamalMultiRecipientCiphertext differentCiphertext = ElGamalMultiRecipientCiphertext.create(differentGamma, validPhis);

		assertEquals(ciphertext, sameCiphertext);
		assertNotEquals(ciphertext, differentCiphertext);
	}

	@Test
	@DisplayName("has valid equals for the phis")
	void phisEqualsTest() {
		final List<GqElement> differentPhis = genDifferentPhis();

		final ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertext.create(validGamma, validPhis);
		final ElGamalMultiRecipientCiphertext sameCiphertext = ElGamalMultiRecipientCiphertext.create(validGamma, validPhis);
		final ElGamalMultiRecipientCiphertext differentCiphertext = ElGamalMultiRecipientCiphertext.create(validGamma, differentPhis);

		assertEquals(ciphertext, sameCiphertext);
		assertNotEquals(ciphertext, differentCiphertext);
	}

	@Test
	@DisplayName("has valid hashCode")
	void hashCodeTest() {
		final GqElement differentGamma = genDifferentGamma();

		final ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertext.create(validGamma, validPhis);
		final ElGamalMultiRecipientCiphertext sameCiphertext = ElGamalMultiRecipientCiphertext.create(validGamma, validPhis);
		final ElGamalMultiRecipientCiphertext differentCiphertext = ElGamalMultiRecipientCiphertext.create(differentGamma, validPhis);

		assertEquals(ciphertext.hashCode(), sameCiphertext.hashCode());
		assertNotEquals(ciphertext.hashCode(), differentCiphertext.hashCode());
	}

	@Test
	@DisplayName("as neutral element contains only 1s")
	void neutralElementTest() {
		int n = new SecureRandom().nextInt(10) + 1;
		ElGamalMultiRecipientCiphertext neutralElement = ElGamalMultiRecipientCiphertext.neutralElement(n, gqGroup);

		GqElement one = gqGroup.getIdentity();
		List<GqElement> ones = Stream.generate(() -> one).limit(n + 1).collect(toList());

		assertEquals(ones, neutralElement.stream().collect(toList()));
		assertEquals(n, neutralElement.size());
	}

	@Test
	@DisplayName("as neutral element with size 0 throws an IllegalArgumentException")
	void neutralElementWithSizeZero() {
		Exception exception = assertThrows(IllegalArgumentException.class, () -> ElGamalMultiRecipientCiphertext.neutralElement(0, gqGroup));
		assertEquals("The neutral ciphertext must have at least one phi.", exception.getMessage());
	}

	@Test
	@DisplayName("as neutral element with null group throws a NullPointerException")
	void neutralElementWithNullGroupTest() {
		assertThrows(NullPointerException.class, () -> ElGamalMultiRecipientCiphertext.neutralElement(1, null));
	}

	private static GqElement genOtherGroupGamma(final GqGroup otherGroup) {
		final GqGroupGenerator otherGroupGenerator = new GqGroupGenerator(otherGroup);

		GqElement otherGroupGamma;
		do {
			otherGroupGamma = otherGroupGenerator.genNonIdentityMember();
		} while (otherGroupGamma.equals(otherGroup.getGenerator()));
		return otherGroupGamma;
	}

	private GqElement genDifferentGamma() {
		GqElement differentGamma;
		do {
			differentGamma = gqGroupGenerator.genNonIdentityMember();
		} while (differentGamma.equals(validGamma) || differentGamma.equals(gqGroup.getGenerator()));
		return differentGamma;
	}

	private List<GqElement> genDifferentPhis() {
		List<GqElement> differentPhis;
		do {
			differentPhis = Arrays.asList(gqGroupGenerator.genMember(), gqGroupGenerator.genMember());
		} while (differentPhis.equals(validPhis));
		return differentPhis;
	}

	private List<GqElement> genOtherGroupPhis(final GqGroup otherGroup) {
		final GqGroupGenerator otherGroupGenerator = new GqGroupGenerator(otherGroup);

		return Arrays.asList(otherGroupGenerator.genMember(), otherGroupGenerator.genMember());
	}

	// ===============================================================================================================================================
	// Multiplication tests.
	// ===============================================================================================================================================

	// Provides parameters for the multiplyTest.
	static Stream<Arguments> jsonFileArgumentProvider() {

		final List<TestParameters> parametersList = TestParameters.fromResource("/elgamal/get-ciphertext-product.json");

		return parametersList.stream().parallel().map(testParameters -> {
			// Context.
			final JsonData context = testParameters.getContext();
			final BigInteger p = context.get("p", BigInteger.class);
			final BigInteger q = context.get("q", BigInteger.class);
			final BigInteger g = context.get("g", BigInteger.class);

			try (MockedStatic<SecurityLevelConfig> mockedSecurityLevel = mockStatic(SecurityLevelConfig.class)) {
				mockedSecurityLevel.when(SecurityLevelConfig::getSystemSecurityLevel).thenReturn(testParameters.getSecurityLevel());
				final GqGroup group = new GqGroup(p, q, g);

				// Parse first ciphertext parameters.
				final JsonData upperCa = testParameters.getInput().getJsonData("upper_c_a");

				final GqElement gammaA = GqElementFactory.fromValue(upperCa.get("gamma", BigInteger.class), group);
				final BigInteger[] phisAArray = upperCa.get("phis", BigInteger[].class);
				final List<GqElement> phisA = Arrays.stream(phisAArray).map(phiA -> GqElementFactory.fromValue(phiA, group)).collect(toList());

				// Parse second ciphertext parameters.
				final JsonData upperCb = testParameters.getInput().getJsonData("upper_c_b");

				final GqElement gammaB = GqElementFactory.fromValue(upperCb.get("gamma", BigInteger.class), group);
				final BigInteger[] phisBArray = upperCb.get("phis", BigInteger[].class);
				final List<GqElement> phisB = Arrays.stream(phisBArray).map(phi -> GqElementFactory.fromValue(phi, group)).collect(toList());

				// Parse multiplication result parameters.
				final JsonData outputJsonData = testParameters.getOutput();

				final GqElement gammaRes = GqElementFactory.fromValue(outputJsonData.get("gamma", BigInteger.class), group);
				final BigInteger[] phisOutput = outputJsonData.get("phis", BigInteger[].class);
				final List<GqElement> phisRes = Arrays.stream(phisOutput).map(phi -> GqElementFactory.fromValue(phi, group)).collect(toList());

				return Arguments.of(gammaA, phisA, gammaB, phisB, gammaRes, phisRes, testParameters.getDescription());
			}
		});
	}

	@ParameterizedTest
	@MethodSource("jsonFileArgumentProvider")
	@DisplayName("with a valid other ciphertext gives expected result")
	void multiplyWithRealValuesTest(final GqElement gammaA, final List<GqElement> phisA, final GqElement gammaB, final List<GqElement> phisB,
			final GqElement gammaRes, final List<GqElement> phisRes, final String description) {

		// Create first ciphertext.
		final ElGamalMultiRecipientCiphertext ciphertextA = ElGamalMultiRecipientCiphertext.create(gammaA, phisA);

		// Create second ciphertext.
		final ElGamalMultiRecipientCiphertext ciphertextB = ElGamalMultiRecipientCiphertext.create(gammaB, phisB);

		// Expected multiplication result.
		final ElGamalMultiRecipientCiphertext ciphertextRes = ElGamalMultiRecipientCiphertext.create(gammaRes, phisRes);

		assertEquals(ciphertextRes, ciphertextA.multiply(ciphertextB), String.format("assertion failed for: %s", description));
	}

	@Test
	void multiplyTest() {

		final GqGroup group = new GqGroup(BigInteger.valueOf(11), BigInteger.valueOf(5), BigInteger.valueOf(3));

		// Create first ciphertext.
		final GqElement gammaA = GqElementFactory.fromValue(BigInteger.valueOf(4), group);
		final List<GqElement> phisA = Arrays
				.asList(GqElementFactory.fromValue(BigInteger.valueOf(3), group), GqElementFactory.fromValue(BigInteger.valueOf(5), group));
		final ElGamalMultiRecipientCiphertext ciphertextA = ElGamalMultiRecipientCiphertext.create(gammaA, phisA);

		// Create second ciphertext.
		final GqElement gammaB = GqElementFactory.fromValue(BigInteger.valueOf(5), group);
		final List<GqElement> phisB = Arrays
				.asList(GqElementFactory.fromValue(BigInteger.valueOf(9), group), GqElementFactory.fromValue(BigInteger.ONE, group));
		final ElGamalMultiRecipientCiphertext ciphertextB = ElGamalMultiRecipientCiphertext.create(gammaB, phisB);

		// Expected multiplication result.
		final GqElement gammaRes = GqElementFactory.fromValue(BigInteger.valueOf(9), group);
		final List<GqElement> phisRes = Arrays.asList(GqElementFactory.fromValue(BigInteger.valueOf(5), group),
				GqElementFactory.fromValue(BigInteger.valueOf(5),
						group));
		final ElGamalMultiRecipientCiphertext ciphertextRes = ElGamalMultiRecipientCiphertext.create(gammaRes, phisRes);

		assertEquals(ciphertextRes, ciphertextA.multiply(ciphertextB));
	}

	@Test
	@DisplayName("with an identity ciphertext (1, 1, 1) yields the same ciphertext")
	void multiplyWithIdentityTest() {
		final GqGroup group = GroupTestData.getGqGroup();
		GqGroupGenerator generator = new GqGroupGenerator(group);
		GqElement element1 = generator.genMember();
		GqElement element2 = generator.genMember();

		// Create first ciphertext.
		ElGamalMultiRecipientMessage message = new ElGamalMultiRecipientMessage(Arrays.asList(element1, element2));
		ZqElement exponent = ZqElement.create(randomService.genRandomInteger(group.getQ()), ZqGroup.sameOrderAs(group));
		ElGamalMultiRecipientPublicKey publicKey = ElGamalMultiRecipientKeyPair.genKeyPair(group, 2, randomService).getPublicKey();
		final ElGamalMultiRecipientCiphertext ciphertextA = ElGamalMultiRecipientCiphertext.getCiphertext(message, exponent, publicKey);

		// Create identity ciphertext.
		final ElGamalMultiRecipientCiphertext ciphertextIdentity = ElGamalMultiRecipientCiphertext.neutralElement(2, group);

		assertEquals(ciphertextA, ciphertextA.multiply(ciphertextIdentity));
	}

	@Test
	@DisplayName("with a null ciphertext throws NullPointerException")
	void multiplyWithNullOtherShouldThrow() {
		final ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertext.create(validGamma, validPhis);

		assertThrows(NullPointerException.class, () -> ciphertext.multiply(null));
	}

	@Test
	@DisplayName("with a ciphertext from another group throws IllegalArgumentException")
	void multiplyWithDifferentGroupOtherShouldThrow() {
		final ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertext.create(validGamma, validPhis);

		final GqGroup otherGroup = new GqGroup(BigInteger.valueOf(7), BigInteger.valueOf(3), BigInteger.valueOf(2));
		final GqElement otherGroupGamma = genOtherGroupGamma(otherGroup);
		final List<GqElement> otherGroupPhis = genOtherGroupPhis(otherGroup);
		final ElGamalMultiRecipientCiphertext other = ElGamalMultiRecipientCiphertext.create(otherGroupGamma, otherGroupPhis);

		assertThrows(IllegalArgumentException.class, () -> ciphertext.multiply(other));
	}

	@Test
	@DisplayName("with a ciphertext with a different number of phis throws IllegalArgumentException")
	void multiplyWithDifferentSizePhisShouldThrow() {
		final ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertext.create(validGamma, validPhis);

		final ImmutableList<GqElement> differentSizePhis = ImmutableList.of(validPhis.get(0));
		final ElGamalMultiRecipientCiphertext other = ElGamalMultiRecipientCiphertext.create(validGamma, differentSizePhis);

		assertThrows(IllegalArgumentException.class, () -> ciphertext.multiply(other));
	}

	@Test
	@DisplayName("exponentiate the ciphertext")
	void decryptedExponentiatedCiphertextAndExponentiatedMessageShouldBeEqual() {
		int noOfMessageElements = 5;

		ZqGroup zqGroup = ZqGroup.sameOrderAs(gqGroup);
		ZqElement exponent = ZqElement.create(randomService.genRandomInteger(zqGroup.getQ()), zqGroup);
		ElGamalMultiRecipientMessage originalMessage = elGamalGenerator.genRandomMessage(noOfMessageElements);
		ElGamalMultiRecipientKeyPair keyPair = ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, noOfMessageElements, randomService);
		ElGamalMultiRecipientCiphertext ciphertext = ElGamalGenerator.encryptMessage(originalMessage, keyPair, zqGroup);

		ElGamalMultiRecipientCiphertext exponentiatedCiphertext = ciphertext.exponentiate(exponent);
		ElGamalMultiRecipientMessage decryptedExponentiatedCipherText = ElGamalMultiRecipientMessage
				.getMessage(exponentiatedCiphertext, keyPair.getPrivateKey());

		List<GqElement> exponentiatedOriginalMessageElements = originalMessage.stream()
				.map(e -> e.exponentiate(exponent))
				.collect(toList());

		ElGamalMultiRecipientMessage exponentiatedOriginalMessage = new ElGamalMultiRecipientMessage(exponentiatedOriginalMessageElements);

		assertEquals(exponentiatedOriginalMessage, decryptedExponentiatedCipherText);
	}

	@Test
	@DisplayName("test vector ciphertext exponentiation")
	void compressedExponentiatedMessagesShouldEqualDecryptedExponentiatedCiphertextVector() {
		int noOfMessageElements = 5;

		GroupVector<ElGamalMultiRecipientMessage, GqGroup> originalMessages = Stream
				.generate(() -> elGamalGenerator.genRandomMessage(noOfMessageElements))
				.limit(noOfMessageElements)
				.collect(toGroupVector());

		ElGamalMultiRecipientKeyPair keyPair = ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, noOfMessageElements, randomService);

		ZqGroup zqGroup = ZqGroup.sameOrderAs(gqGroup);
		GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> elGamalMultiRecipientCiphertexts = originalMessages.stream()
				.map(originalMessage -> ElGamalGenerator.encryptMessage(originalMessage, keyPair, zqGroup))
				.collect(toGroupVector());

		GroupVector<ZqElement, ZqGroup> exponents = Stream
				.generate(() -> ZqElement.create(randomService.genRandomInteger(zqGroup.getQ()), zqGroup))
				.limit(elGamalMultiRecipientCiphertexts.size())
				.collect(toGroupVector());

		ElGamalMultiRecipientCiphertext ciphertextVectorExponentiation = ElGamalMultiRecipientCiphertext
				.getCiphertextVectorExponentiation(elGamalMultiRecipientCiphertexts, exponents);

		ElGamalMultiRecipientMessage decryptedExponentiatedCipherText =
				ElGamalMultiRecipientMessage.getMessage(ciphertextVectorExponentiation, keyPair.getPrivateKey());

		List<List<GqElement>> exponentiatedOriginalMessageElements = IntStream.range(0, originalMessages.size())
				.mapToObj(i -> originalMessages.get(i).stream()
						.map(m -> m.exponentiate(exponents.get(i)))
						.collect(toList()))
				.collect(toList());

		GroupMatrix<GqElement, GqGroup> matrix = GroupMatrix.fromRows(exponentiatedOriginalMessageElements);

		ElGamalMultiRecipientMessage exponentiatedOriginalMessage = matrix.columnStream()
				.map(col -> col.stream()
						.reduce(gqGroup.getIdentity(), GqElement::multiply))
				.collect(collectingAndThen(toList(), ElGamalMultiRecipientMessage::new));

		assertEquals(exponentiatedOriginalMessage, decryptedExponentiatedCipherText);
	}

	@Test
	void testCiphertextVectorExponentiationNullAndEmptyParameterValidation() {

		GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> emptyCipherTexts = GroupVector.of();
		GroupVector<ZqElement, ZqGroup> emptyExponents = GroupVector.of();

		assertThrows(NullPointerException.class, () -> ElGamalMultiRecipientCiphertext.getCiphertextVectorExponentiation(null, emptyExponents));
		assertThrows(NullPointerException.class, () -> ElGamalMultiRecipientCiphertext.getCiphertextVectorExponentiation(emptyCipherTexts, null));

		IllegalArgumentException emptyIllegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> ElGamalMultiRecipientCiphertext.getCiphertextVectorExponentiation(emptyCipherTexts, emptyExponents));

		assertEquals("Ciphertexts should not be empty", emptyIllegalArgumentException.getMessage());
	}

	@Test
	void testCiphertextVectorExponentiationParameterValidation() {
		int noOfMessageElements = 5;

		List<ElGamalMultiRecipientMessage> originalMessages = Stream
				.generate(() -> elGamalGenerator.genRandomMessage(noOfMessageElements))
				.limit(noOfMessageElements)
				.collect(toList());

		ZqGroup zqGroup = ZqGroup.sameOrderAs(gqGroup);
		GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> fiveCipherTexts = originalMessages.stream()
				.map(originalMessage -> ElGamalGenerator
						.encryptMessage(originalMessage, ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, originalMessage.size(), randomService),
								zqGroup))
				.collect(toGroupVector());

		GroupVector<ZqElement, ZqGroup> fourExponents = Stream
				.generate(() -> ZqElement.create(randomService.genRandomInteger(zqGroup.getQ()), zqGroup))
				.limit(fiveCipherTexts.size() - 1)
				.collect(toGroupVector());

		IllegalArgumentException sizeIllegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> ElGamalMultiRecipientCiphertext.getCiphertextVectorExponentiation(fiveCipherTexts, fourExponents));

		assertEquals("There should be a matching ciphertext for every exponent.", sizeIllegalArgumentException.getMessage());

		GqGroup differentgqGroup = GroupTestData.getDifferentGqGroup(gqGroup);

		GroupVector<ZqElement, ZqGroup> fiveExponents = Stream
				.generate(() -> ZqElement.create(randomService.genRandomInteger(differentgqGroup.getQ()), ZqGroup.sameOrderAs(differentgqGroup)))
				.limit(fiveCipherTexts.size())
				.collect(toGroupVector());

		IllegalArgumentException differentQIllegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> ElGamalMultiRecipientCiphertext.getCiphertextVectorExponentiation(fiveCipherTexts, fiveExponents));
		assertEquals("Ciphertexts and exponents must be of the same group.", differentQIllegalArgumentException.getMessage());
	}

	@Nested
	@DisplayName("calling getPartialDecryption with")
	class PartialDecryptionTest {
		private int secretKeySize;

		private ElGamalMultiRecipientCiphertext ciphertext;
		private ElGamalMultiRecipientPrivateKey secretKey;

		@BeforeEach
		void setUpEach() {
			ciphertext = ElGamalMultiRecipientCiphertext.create(validGamma, validPhis);

			secretKeySize = ciphertext.size();
			secretKey = elGamalGenerator.genRandomPrivateKey(secretKeySize);
		}

		@Test
		@DisplayName("a null secret key parameter throws a NullPointerException.")
		void getPartialDecryptionParametersShouldBeNotNull() {
			assertThrows(NullPointerException.class, () -> ciphertext.getPartialDecryption(null));
		}

		@Test
		@DisplayName("a ciphertext and a secret key with different order throws an IllegalArgumentException.")
		void getPartialDecryptionCiphertextAndSecretKeyShouldBePartOfSameGroup() {

			final ElGamalMultiRecipientPrivateKey secretKey =
					new ElGamalGenerator(GroupTestData.getDifferentGqGroup(gqGroup)).genRandomPrivateKey(secretKeySize);

			final IllegalArgumentException illegalArgumentException =
					assertThrows(IllegalArgumentException.class, () -> ciphertext.getPartialDecryption(secretKey));

			assertEquals("Ciphertext and secret key must belong to groups of same order.", illegalArgumentException.getMessage());
		}

		@Test
		@DisplayName("a ciphertext containing more message elements than private key elements throws an IllegalArgumentException.")
		void getPartialDecryptionSecretKeySizeShouldBeAtLeastSameAsCiphertextSize() {

			final ElGamalMultiRecipientPrivateKey secretKey = elGamalGenerator.genRandomPrivateKey(ciphertext.size() - 1);

			final IllegalArgumentException illegalArgumentException =
					assertThrows(IllegalArgumentException.class, () -> ciphertext.getPartialDecryption(secretKey));

			assertEquals("There cannot be more message elements than private key elements.", illegalArgumentException.getMessage());
		}

		@Test
		@DisplayName("with correct parameters returns the expected result.")
		void getPartialDecryptionReturnsExpectedResult() {

			final ElGamalMultiRecipientCiphertext partialDecryption = assertDoesNotThrow(() -> ciphertext.getPartialDecryption(secretKey));

			assertAll(
					() -> assertEquals(ciphertext.getGamma(), partialDecryption.getGamma()),
					() -> assertEquals(ciphertext.size(), partialDecryption.size()));
		}
	}
}
