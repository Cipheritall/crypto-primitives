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
package ch.post.it.evoting.cryptoprimitives.internal.zeroknowledgeproofs;

import static ch.post.it.evoting.cryptoprimitives.internal.zeroknowledgeproofs.PlaintextEqualityProofService.computePhiPlaintextEquality;
import static ch.post.it.evoting.cryptoprimitives.math.GqElement.GqElementFactory;
import static ch.post.it.evoting.cryptoprimitives.math.GroupVector.toGroupVector;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedStatic;

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamal;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientMessage;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.internal.elgamal.ElGamalService;
import ch.post.it.evoting.cryptoprimitives.internal.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.internal.hashing.TestHashService;
import ch.post.it.evoting.cryptoprimitives.internal.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.internal.securitylevel.SecurityLevelConfig;
import ch.post.it.evoting.cryptoprimitives.test.tools.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.JsonData;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.TestParameters;
import ch.post.it.evoting.cryptoprimitives.zeroknowledgeproofs.PlaintextEqualityProof;

@DisplayName("PlaintextEqualityProofService calling")
class PlaintextEqualityProofServiceTest extends TestGroupSetup {

	private static final ElGamal elGamal = new ElGamalService();
	private static ElGamalGenerator elGamalGenerator;
	private static RandomService randomService;
	private static PlaintextEqualityProofService plaintextEqualityProofService;

	@BeforeAll
	static void setUpAll() {
		elGamalGenerator = new ElGamalGenerator(gqGroup);
		randomService = new RandomService();

		final HashService hashService = TestHashService.create(gqGroup.getQ());
		plaintextEqualityProofService = new PlaintextEqualityProofService(randomService, hashService);
	}

	@Nested
	@DisplayName("computePhiPlaintextEquality with")
	class ComputePhiPlaintextEquality {

		private GroupVector<ZqElement, ZqGroup> preImage;
		private GqElement firstPublicKey;
		private GqElement secondPublicKey;

		@BeforeEach
		void setUp() {
			preImage = zqGroupGenerator.genRandomZqElementVector(2);
			firstPublicKey = gqGroupGenerator.genMember();
			secondPublicKey = gqGroupGenerator.genMember();
		}

		@Test
		@DisplayName("valid parameters does not throw")
		void validParams() {
			final GroupVector<GqElement, GqGroup> image = computePhiPlaintextEquality(preImage, firstPublicKey, secondPublicKey);
			assertEquals(3, image.size());
		}

		@Test
		@DisplayName("null parameters throws NullPointerException")
		void nullParams() {
			assertThrows(NullPointerException.class, () -> computePhiPlaintextEquality(null, firstPublicKey, secondPublicKey));
			assertThrows(NullPointerException.class, () -> computePhiPlaintextEquality(preImage, null, secondPublicKey));
			assertThrows(NullPointerException.class, () -> computePhiPlaintextEquality(preImage, firstPublicKey, null));
		}

		@Test
		@DisplayName("wrong size preImage throws IllegalArgumentException")
		void wrongSizePreImage() {
			final GroupVector<ZqElement, ZqGroup> tooShortPreImage = zqGroupGenerator.genRandomZqElementVector(1);
			final IllegalArgumentException tooShortException = assertThrows(IllegalArgumentException.class,
					() -> computePhiPlaintextEquality(tooShortPreImage, firstPublicKey, secondPublicKey));
			assertEquals("The preImage must be of size 2.", tooShortException.getMessage());

			final GroupVector<ZqElement, ZqGroup> tooLongPreImage = zqGroupGenerator.genRandomZqElementVector(3);
			final IllegalArgumentException tooLongException = assertThrows(IllegalArgumentException.class,
					() -> computePhiPlaintextEquality(tooLongPreImage, firstPublicKey, secondPublicKey));
			assertEquals("The preImage must be of size 2.", tooLongException.getMessage());
		}

		@Test
		@DisplayName("public keys having different groups throws IllegalArgumentException")
		void keysDiffGroups() {
			final GqElement otherGroupFirstPublicKey = otherGqGroupGenerator.genMember();
			final IllegalArgumentException otherGroupFirstException = assertThrows(IllegalArgumentException.class,
					() -> computePhiPlaintextEquality(preImage, otherGroupFirstPublicKey, secondPublicKey));
			assertEquals("The two public keys must have the same group.", otherGroupFirstException.getMessage());

			final GqElement otherGroupSecondPublicKey = otherGqGroupGenerator.genMember();
			final IllegalArgumentException otherGroupSecondException = assertThrows(IllegalArgumentException.class,
					() -> computePhiPlaintextEquality(preImage, firstPublicKey, otherGroupSecondPublicKey));
			assertEquals("The two public keys must have the same group.", otherGroupSecondException.getMessage());
		}

		@Test
		@DisplayName("preImage and keys having different groups throws IllegalArgumentException")
		void preImageAndKeysDiffGroups() {
			final GroupVector<ZqElement, ZqGroup> otherGroupPreImage = otherZqGroupGenerator.genRandomZqElementVector(2);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> computePhiPlaintextEquality(otherGroupPreImage, firstPublicKey, secondPublicKey));
			assertEquals("The preImage and public keys must have the same group order.", exception.getMessage());
		}

		@Test
		@DisplayName("specific values gives expected image")
		void specificValues() {
			final GqGroup gqGroup = new GqGroup(BigInteger.valueOf(11), BigInteger.valueOf(5), BigInteger.valueOf(3));
			final ZqGroup zqGroup = new ZqGroup(BigInteger.valueOf(5));
			final ZqElement zero = ZqElement.create(BigInteger.valueOf(0), zqGroup);
			final ZqElement three = ZqElement.create(BigInteger.valueOf(3), zqGroup);
			final GqElement one = GqElementFactory.fromValue(BigInteger.valueOf(1), gqGroup);
			final GqElement four = GqElementFactory.fromValue(BigInteger.valueOf(4), gqGroup);
			final GqElement five = GqElementFactory.fromValue(BigInteger.valueOf(5), gqGroup);
			final GqElement nine = GqElementFactory.fromValue(BigInteger.valueOf(9), gqGroup);

			final GroupVector<GqElement, GqGroup> image = computePhiPlaintextEquality(GroupVector.of(zero, three), four, nine);
			final GroupVector<GqElement, GqGroup> expectedImage = GroupVector.of(one, five, four);

			assertEquals(expectedImage, image);
		}

	}

	@Nested
	@DisplayName("genPlaintextEquality with")
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	class GenPlaintextEquality {

		private static final int STR_LEN = 4;

		private ElGamalMultiRecipientCiphertext firstCiphertext;
		private ElGamalMultiRecipientCiphertext secondCiphertext;
		private GqElement firstPublicKey;
		private GqElement secondPublicKey;
		private GroupVector<ZqElement, ZqGroup> randomness;
		private List<String> auxiliaryInformation;

		@BeforeEach
		void setUp() {
			final ElGamalMultiRecipientMessage plaintext = new ElGamalMultiRecipientMessage(gqGroupGenerator.genRandomGqElementVector(1));

			randomness = zqGroupGenerator.genRandomZqElementVector(2);
			firstPublicKey = gqGroupGenerator.genMember();
			secondPublicKey = gqGroupGenerator.genMember();
			firstCiphertext = elGamal.getCiphertext(plaintext, randomness.get(0),
					new ElGamalMultiRecipientPublicKey(Collections.singletonList(firstPublicKey)));
			secondCiphertext = elGamal.getCiphertext(plaintext, randomness.get(1),
					new ElGamalMultiRecipientPublicKey(Collections.singletonList(secondPublicKey)));

			auxiliaryInformation = Arrays.asList(randomService.genRandomBase16String(STR_LEN), randomService.genRandomBase64String(STR_LEN));
		}

		@Test
		@DisplayName("valid parameters does not throw")
		void validParams() {
			assertDoesNotThrow(
					() -> plaintextEqualityProofService.genPlaintextEqualityProof(firstCiphertext, secondCiphertext, firstPublicKey, secondPublicKey,
							randomness, auxiliaryInformation));
		}

		@Test
		@DisplayName("null parameters throws NullPointerException")
		void nullParams() {
			assertThrows(NullPointerException.class, () -> plaintextEqualityProofService
					.genPlaintextEqualityProof(null, secondCiphertext, firstPublicKey, secondPublicKey, randomness, auxiliaryInformation));
			assertThrows(NullPointerException.class, () -> plaintextEqualityProofService
					.genPlaintextEqualityProof(firstCiphertext, null, firstPublicKey, secondPublicKey, randomness, auxiliaryInformation));
			assertThrows(NullPointerException.class, () -> plaintextEqualityProofService
					.genPlaintextEqualityProof(firstCiphertext, secondCiphertext, null, secondPublicKey, randomness, auxiliaryInformation));
			assertThrows(NullPointerException.class, () -> plaintextEqualityProofService
					.genPlaintextEqualityProof(firstCiphertext, secondCiphertext, firstPublicKey, null, randomness, auxiliaryInformation));
			assertThrows(NullPointerException.class, () -> plaintextEqualityProofService
					.genPlaintextEqualityProof(firstCiphertext, secondCiphertext, firstPublicKey, secondPublicKey, null, auxiliaryInformation));
			assertThrows(NullPointerException.class, () -> plaintextEqualityProofService
					.genPlaintextEqualityProof(firstCiphertext, secondCiphertext, firstPublicKey, secondPublicKey, randomness, null));
		}

		@Test
		@DisplayName("auxiliary information containing null throws IllegalArgumentException")
		void auxiliaryInformationWithNull() {
			auxiliaryInformation.set(0, null);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> plaintextEqualityProofService
					.genPlaintextEqualityProof(firstCiphertext, secondCiphertext, firstPublicKey, secondPublicKey, randomness, auxiliaryInformation));
			assertEquals("The auxiliary information must not contain null objects.", exception.getMessage());
		}

		@Test
		@DisplayName("wrong size ciphertexts throws IllegalArgumentException")
		void wrongSizeCiphertexts() {
			// Wrong first ciphertext.
			final ElGamalMultiRecipientCiphertext wrongSizeFirstCiphertext = elGamalGenerator.genRandomCiphertext(2);

			final IllegalArgumentException firstException = assertThrows(IllegalArgumentException.class, () -> plaintextEqualityProofService
					.genPlaintextEqualityProof(wrongSizeFirstCiphertext, secondCiphertext, firstPublicKey, secondPublicKey, randomness,
							auxiliaryInformation));
			assertEquals("The first ciphertext must have exactly one phi.", firstException.getMessage());

			// Wrong second ciphertext.
			final ElGamalMultiRecipientCiphertext wrongSizeSecondCiphertext = elGamalGenerator.genRandomCiphertext(2);

			final IllegalArgumentException secondException = assertThrows(IllegalArgumentException.class, () -> plaintextEqualityProofService
					.genPlaintextEqualityProof(firstCiphertext, wrongSizeSecondCiphertext, firstPublicKey, secondPublicKey, randomness,
							auxiliaryInformation));
			assertEquals("The second ciphertext must have exactly one phi.", secondException.getMessage());
		}

		@Test
		@DisplayName("wrong size randomness throws IllegalArgumentException")
		void wrongSizeRandomness() {
			final GroupVector<ZqElement, ZqGroup> shortRandomness = zqGroupGenerator.genRandomZqElementVector(1);
			final IllegalArgumentException shortException = assertThrows(IllegalArgumentException.class, () -> plaintextEqualityProofService
					.genPlaintextEqualityProof(firstCiphertext, secondCiphertext, firstPublicKey, secondPublicKey, shortRandomness,
							auxiliaryInformation));
			assertEquals("The randomness vector must have exactly two elements.", shortException.getMessage());

			final GroupVector<ZqElement, ZqGroup> longRandomness = zqGroupGenerator.genRandomZqElementVector(3);
			final IllegalArgumentException longException = assertThrows(IllegalArgumentException.class, () -> plaintextEqualityProofService
					.genPlaintextEqualityProof(firstCiphertext, secondCiphertext, firstPublicKey, secondPublicKey, longRandomness,
							auxiliaryInformation));
			assertEquals("The randomness vector must have exactly two elements.", longException.getMessage());
		}

		Stream<Arguments> differentGroupInputsProvider() {
			firstCiphertext = elGamalGenerator.genRandomCiphertext(1);
			secondCiphertext = elGamalGenerator.genRandomCiphertext(1);
			firstPublicKey = gqGroupGenerator.genMember();
			secondPublicKey = gqGroupGenerator.genMember();
			randomness = zqGroupGenerator.genRandomZqElementVector(2);
			auxiliaryInformation = Arrays.asList(randomService.genRandomBase16String(STR_LEN), randomService.genRandomBase64String(STR_LEN));

			final ElGamalGenerator otherElGamalGenerator = new ElGamalGenerator(otherGqGroup);

			final ElGamalMultiRecipientCiphertext otherFirstCiphertext = otherElGamalGenerator.genRandomCiphertext(1);
			final ElGamalMultiRecipientCiphertext otherSecondCiphertext = otherElGamalGenerator.genRandomCiphertext(1);
			final GqElement otherFirstPublicKey = otherGqGroupGenerator.genMember();
			final GqElement otherSecondPublicKey = otherGqGroupGenerator.genMember();

			return Stream.of(
					Arguments.of(otherFirstCiphertext, secondCiphertext, firstPublicKey, secondPublicKey),
					Arguments.of(firstCiphertext, otherSecondCiphertext, firstPublicKey, secondPublicKey),
					Arguments.of(firstCiphertext, secondCiphertext, otherFirstPublicKey, secondPublicKey),
					Arguments.of(firstCiphertext, secondCiphertext, firstPublicKey, otherSecondPublicKey)
			);
		}

		@ParameterizedTest
		@MethodSource("differentGroupInputsProvider")
		@DisplayName("not all inputs from same GqGroup throws IllegalArgumentException")
		void differentGqGroup(final ElGamalMultiRecipientCiphertext firstCiphertext, final ElGamalMultiRecipientCiphertext secondCiphertext,
				final GqElement firstPublicKey, final GqElement secondPublicKey) {

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> plaintextEqualityProofService
					.genPlaintextEqualityProof(firstCiphertext, secondCiphertext, firstPublicKey, secondPublicKey, randomness,
							auxiliaryInformation));
			assertEquals("The ciphertexts and public keys must all belong to the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("randomness with group of different order throws IllegalArgumentException")
		void differentOrderRandomness() {
			final GroupVector<ZqElement, ZqGroup> otherRandomness = otherZqGroupGenerator.genRandomZqElementVector(2);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> plaintextEqualityProofService
					.genPlaintextEqualityProof(firstCiphertext, secondCiphertext, firstPublicKey, secondPublicKey, otherRandomness,
							auxiliaryInformation));
			assertEquals("The randomness and ciphertexts and public keys must have the same group order.", exception.getMessage());
		}
	}

	@Nested
	@DisplayName("verifyPlaintextEquality with")
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	class VerifyPlaintextEquality {

		private static final int STR_LEN = 4;

		private ElGamalMultiRecipientCiphertext firstCiphertext;
		private ElGamalMultiRecipientCiphertext secondCiphertext;
		private GqElement firstPublicKey;
		private GqElement secondPublicKey;
		private GroupVector<ZqElement, ZqGroup> randomness;
		private PlaintextEqualityProof plaintextEqualityProof;
		private List<String> auxiliaryInformation;

		@BeforeEach
		void setUp() {
			final ElGamalMultiRecipientMessage plaintext = elGamalGenerator.genRandomMessage(1);

			randomness = zqGroupGenerator.genRandomZqElementVector(2);
			firstPublicKey = gqGroupGenerator.genMember();
			secondPublicKey = gqGroupGenerator.genMember();
			firstCiphertext = elGamal.getCiphertext(plaintext, randomness.get(0),
					new ElGamalMultiRecipientPublicKey(Collections.singletonList(firstPublicKey)));
			secondCiphertext = elGamal.getCiphertext(plaintext, randomness.get(1),
					new ElGamalMultiRecipientPublicKey(Collections.singletonList(secondPublicKey)));

			auxiliaryInformation = Arrays.asList(randomService.genRandomBase16String(STR_LEN), randomService.genRandomBase64String(STR_LEN));

			plaintextEqualityProof = plaintextEqualityProofService.genPlaintextEqualityProof(firstCiphertext, secondCiphertext, firstPublicKey,
					secondPublicKey, randomness, auxiliaryInformation);
		}

		@Test
		@DisplayName("valid parameters returns true")
		void validParams() {
			assertTrue(plaintextEqualityProofService.verifyPlaintextEquality(firstCiphertext, secondCiphertext, firstPublicKey, secondPublicKey,
					plaintextEqualityProof, auxiliaryInformation));
		}

		@Test
		@DisplayName("empty auxiliary information returns true")
		void emptyAux() {
			final PlaintextEqualityProof plaintextEqualityProof = plaintextEqualityProofService.genPlaintextEqualityProof(firstCiphertext,
					secondCiphertext, firstPublicKey, secondPublicKey, randomness, Collections.emptyList());

			assertTrue(plaintextEqualityProofService.verifyPlaintextEquality(firstCiphertext, secondCiphertext, firstPublicKey, secondPublicKey,
					plaintextEqualityProof, Collections.emptyList()));
		}

		@Test
		@DisplayName("null parameters throws NullPointerException")
		void nullParams() {
			assertThrows(NullPointerException.class, () -> plaintextEqualityProofService
					.verifyPlaintextEquality(null, secondCiphertext, firstPublicKey, secondPublicKey, plaintextEqualityProof, auxiliaryInformation));
			assertThrows(NullPointerException.class, () -> plaintextEqualityProofService
					.verifyPlaintextEquality(firstCiphertext, null, firstPublicKey, secondPublicKey, plaintextEqualityProof, auxiliaryInformation));
			assertThrows(NullPointerException.class, () -> plaintextEqualityProofService
					.verifyPlaintextEquality(firstCiphertext, secondCiphertext, null, secondPublicKey, plaintextEqualityProof, auxiliaryInformation));
			assertThrows(NullPointerException.class, () -> plaintextEqualityProofService
					.verifyPlaintextEquality(firstCiphertext, secondCiphertext, firstPublicKey, null, plaintextEqualityProof, auxiliaryInformation));
			assertThrows(NullPointerException.class, () -> plaintextEqualityProofService
					.verifyPlaintextEquality(firstCiphertext, secondCiphertext, firstPublicKey, secondPublicKey, null, auxiliaryInformation));
			assertThrows(NullPointerException.class, () -> plaintextEqualityProofService
					.verifyPlaintextEquality(firstCiphertext, secondCiphertext, firstPublicKey, secondPublicKey, plaintextEqualityProof, null));
		}

		@Test
		@DisplayName("auxiliary information containing null throws IllegalArgumentException")
		void auxiliaryInformationWithNull() {
			auxiliaryInformation.set(0, null);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> plaintextEqualityProofService
					.verifyPlaintextEquality(firstCiphertext, secondCiphertext, firstPublicKey, secondPublicKey, plaintextEqualityProof,
							auxiliaryInformation));
			assertEquals("The auxiliary information must not contain null objects.", exception.getMessage());
		}

		@Test
		@DisplayName("wrong size ciphertexts throws IllegalArgumentException")
		void wrongSizeCiphertexts() {
			// Wrong first ciphertext.
			final ElGamalMultiRecipientCiphertext wrongSizeFirstCiphertext = elGamalGenerator.genRandomCiphertext(2);

			final IllegalArgumentException firstException = assertThrows(IllegalArgumentException.class, () -> plaintextEqualityProofService
					.verifyPlaintextEquality(wrongSizeFirstCiphertext, secondCiphertext, firstPublicKey, secondPublicKey, plaintextEqualityProof,
							auxiliaryInformation));
			assertEquals("The first ciphertext must have exactly one phi.", firstException.getMessage());

			// Wrong second ciphertext.
			final ElGamalMultiRecipientCiphertext wrongSizeSecondCiphertext = elGamalGenerator.genRandomCiphertext(2);

			final IllegalArgumentException secondException = assertThrows(IllegalArgumentException.class, () -> plaintextEqualityProofService
					.verifyPlaintextEquality(firstCiphertext, wrongSizeSecondCiphertext, firstPublicKey, secondPublicKey, plaintextEqualityProof,
							auxiliaryInformation));
			assertEquals("The second ciphertext must have exactly one phi.", secondException.getMessage());
		}

		Stream<Arguments> differentGroupInputsProvider() {
			firstCiphertext = elGamalGenerator.genRandomCiphertext(1);
			secondCiphertext = elGamalGenerator.genRandomCiphertext(1);
			firstPublicKey = gqGroupGenerator.genMember();
			secondPublicKey = gqGroupGenerator.genMember();
			randomness = zqGroupGenerator.genRandomZqElementVector(2);
			auxiliaryInformation = Arrays.asList(randomService.genRandomBase16String(STR_LEN), randomService.genRandomBase64String(STR_LEN));
			plaintextEqualityProof = plaintextEqualityProofService.genPlaintextEqualityProof(firstCiphertext, secondCiphertext, firstPublicKey,
					secondPublicKey, randomness, auxiliaryInformation);

			final ElGamalGenerator otherElGamalGenerator = new ElGamalGenerator(otherGqGroup);

			final ElGamalMultiRecipientCiphertext otherFirstCiphertext = otherElGamalGenerator.genRandomCiphertext(1);
			final ElGamalMultiRecipientCiphertext otherSecondCiphertext = otherElGamalGenerator.genRandomCiphertext(1);
			final GqElement otherFirstPublicKey = otherGqGroupGenerator.genMember();
			final GqElement otherSecondPublicKey = otherGqGroupGenerator.genMember();

			return Stream.of(
					Arguments.of(otherFirstCiphertext, secondCiphertext, firstPublicKey, secondPublicKey, plaintextEqualityProof),
					Arguments.of(firstCiphertext, otherSecondCiphertext, firstPublicKey, secondPublicKey, plaintextEqualityProof),
					Arguments.of(firstCiphertext, secondCiphertext, otherFirstPublicKey, secondPublicKey, plaintextEqualityProof),
					Arguments.of(firstCiphertext, secondCiphertext, firstPublicKey, otherSecondPublicKey, plaintextEqualityProof)
			);
		}

		@ParameterizedTest
		@MethodSource("differentGroupInputsProvider")
		@DisplayName("not all inputs from same GqGroup throws IllegalArgumentException")
		void differentGqGroup(final ElGamalMultiRecipientCiphertext firstCiphertext, final ElGamalMultiRecipientCiphertext secondCiphertext,
				final GqElement firstPublicKey, final GqElement secondPublicKey) {

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> plaintextEqualityProofService
					.verifyPlaintextEquality(firstCiphertext, secondCiphertext, firstPublicKey, secondPublicKey, plaintextEqualityProof,
							auxiliaryInformation));
			assertEquals("The ciphertexts and public keys must all belong to the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("not the same group order throws IllegalArgumentException")
		void differentGroupOrder() {

			final PlaintextEqualityProof otherPlaintextEqualityProof = new PlaintextEqualityProof(otherZqGroupGenerator.genRandomZqElementMember(),
					otherZqGroupGenerator.genRandomZqElementVector(2));

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> plaintextEqualityProofService
					.verifyPlaintextEquality(firstCiphertext, secondCiphertext, firstPublicKey, secondPublicKey, otherPlaintextEqualityProof,
							auxiliaryInformation));

			assertEquals("The plaintext equality proof must have the same group order as the ciphertexts and the public keys.",
					exception.getMessage());
		}

		private Stream<Arguments> jsonFileArgumentProvider() {
			final List<TestParameters> parametersList = TestParameters.fromResource("/zeroknowledgeproofs/verify-plaintext-equality.json");

			return parametersList.stream().parallel().map(testParameters -> {
				// Context.
				final JsonData context = testParameters.getContext();
				final BigInteger p = context.get("p", BigInteger.class);
				final BigInteger q = context.get("q", BigInteger.class);
				final BigInteger g = context.get("g", BigInteger.class);

				try (final MockedStatic<SecurityLevelConfig> mockedSecurityLevel = mockStatic(SecurityLevelConfig.class)) {
					mockedSecurityLevel.when(SecurityLevelConfig::getSystemSecurityLevel).thenReturn(testParameters.getSecurityLevel());
					final GqGroup gqGroup = new GqGroup(p, q, g);
					final ZqGroup zqGroup = new ZqGroup(q);

					final JsonData input = testParameters.getInput();

					// Parse firstCiphertext (upper_c) parameters
					final GqElement firstGamma = GqElementFactory.fromValue(input.getJsonData("upper_c").get("gamma", BigInteger.class), gqGroup);
					final List<GqElement> firstPhi = Arrays.stream(input.getJsonData("upper_c").get("phis", BigInteger[].class))
							.map(upperCA -> GqElementFactory.fromValue(upperCA, gqGroup)).toList();

					final ElGamalMultiRecipientCiphertext firstCiphertext = ElGamalMultiRecipientCiphertext.create(firstGamma, firstPhi);

					// Parse secondCiphertext (upper_c_prime) parameters
					final GqElement secondGamma = GqElementFactory.fromValue(input.getJsonData("upper_c_prime").get("gamma", BigInteger.class), gqGroup);;
					final List<GqElement> secondPhi = Arrays.stream(input.getJsonData("upper_c_prime").get("phis", BigInteger[].class))
							.map(upperCA -> GqElementFactory.fromValue(upperCA, gqGroup)).toList();

					final ElGamalMultiRecipientCiphertext secondCiphertext = ElGamalMultiRecipientCiphertext.create(secondGamma, secondPhi);

					// Parse firstPublicKey (h) parameter
					final BigInteger h = input.get("h", BigInteger.class);
					final GqElement firstPublicKey = GqElementFactory.fromValue(h, gqGroup);

					// Parse secondPublicKey (h_prime) parameter
					final BigInteger hPrime = input.get("h_prime", BigInteger.class);
					final GqElement secondPublicKey = GqElementFactory.fromValue(hPrime, gqGroup);

					// Parse plaintextEqualityProof (proof) parameters
					final JsonData proof = input.getJsonData("proof");

					final ZqElement e = ZqElement.create(proof.get("e", BigInteger.class), zqGroup);

					final BigInteger[] zArray = proof.get("z", BigInteger[].class);
					final GroupVector<ZqElement, ZqGroup> z = Arrays.stream(zArray)
							.map(zA -> ZqElement.create(zA, zqGroup))
							.collect(toGroupVector());
					final PlaintextEqualityProof plaintextEqualityProof = new PlaintextEqualityProof(e, z);

					// Parse auxiliaryInformation parameters (i_aux)
					final String[] auxInformation = input.get("i_aux", String[].class);
					final List<String> auxiliaryInformation = Arrays.asList(auxInformation);

					// Parse output parameters
					final JsonData output = testParameters.getOutput();

					final Boolean result = output.get("output", Boolean.class);

					return Arguments
							.of(firstCiphertext, secondCiphertext, firstPublicKey, secondPublicKey, plaintextEqualityProof, auxiliaryInformation,
									result, testParameters.getDescription());
				}
			});
		}

		@ParameterizedTest()
		@MethodSource("jsonFileArgumentProvider")
		@DisplayName("with real values gives expected result")
		void verifyPlaintextEqualityProofWithRealValues(final ElGamalMultiRecipientCiphertext firstCiphertext,
				final ElGamalMultiRecipientCiphertext secondCiphertext,
				final GqElement firstPublicKey, final GqElement secondPublicKey, final PlaintextEqualityProof plaintextEqualityProof,
				final List<String> auxiliaryInformation, final boolean expected, final String description) {

			final PlaintextEqualityProofService plaintextEqualityProofService = new PlaintextEqualityProofService(randomService,
					HashService.getInstance());
			final boolean actual = plaintextEqualityProofService.verifyPlaintextEquality(firstCiphertext, secondCiphertext, firstPublicKey,
					secondPublicKey, plaintextEqualityProof, auxiliaryInformation);
			assertEquals(expected, actual, String.format("assertion failed for: %s", description));

		}
	}
}
