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
package ch.post.it.evoting.cryptoprimitives.elgamal;

import static ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext.getCiphertext;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.JsonData;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.TestParameters;

class ElGamalMultiRecipientCiphertextCreationTest {

	static private final int NUM_RECIPIENTS = 10;

	static private GqGroup gqGroup;
	static private GqElement gqIdentity;
	static private RandomService randomService;
	static private ZqGroup zqGroup;
	static private GqGroupGenerator gqGroupGenerator;
	private static ElGamalMultiRecipientMessage onesMessage;

	private ElGamalMultiRecipientMessage validMessage;
	private ZqElement validExponent;
	private ElGamalMultiRecipientPublicKey validPK;

	@BeforeAll
	static void setUp() {
		gqGroup = GroupTestData.getGqGroup();
		gqIdentity = gqGroup.getIdentity();
		gqGroupGenerator = new GqGroupGenerator(gqGroup);
		zqGroup = ZqGroup.sameOrderAs(gqGroup);
		randomService = new RandomService();
		List<GqElement> ones = Stream.generate(() -> gqGroup.getIdentity()).limit(NUM_RECIPIENTS).collect(Collectors.toList());
		onesMessage = new ElGamalMultiRecipientMessage(ones);
	}

	@BeforeEach
	void setUpEach() {
		List<GqElement> messageElements =
				Stream.generate(() -> gqGroupGenerator.genMember()).limit(NUM_RECIPIENTS).collect(Collectors.toList());
		validMessage = new ElGamalMultiRecipientMessage(messageElements);

		validExponent = ZqElement.create(randomService.genRandomInteger(zqGroup.getQ()), zqGroup);

		validPK = ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, NUM_RECIPIENTS, randomService).getPublicKey();
	}

	@Test
	void testNullMessageThrows() {
		assertThrows(NullPointerException.class, () -> getCiphertext(null, validExponent, validPK));
	}

	@Test
	void testNullExponentThrows() {
		assertThrows(NullPointerException.class, () -> getCiphertext(validMessage, null, validPK));
	}

	@Test
	void testNullPublicKeyThrows() {
		assertThrows(NullPointerException.class, () -> getCiphertext(validMessage, validExponent, null));
	}

	@Test
	void testExponentFromDifferentQThrows() {
		ZqGroup otherGroup = GroupTestData.getDifferentZqGroup(zqGroup);
		ZqElement otherGroupExponent = ZqElement.create(randomService.genRandomInteger(otherGroup.getQ()), otherGroup);

		assertThrows(IllegalArgumentException.class, () -> getCiphertext(validMessage, otherGroupExponent, validPK));
	}

	@Test
	void testMessageAndPublicKeyFromDifferentGroupsThrows() {
		GqGroup otherGroup = GroupTestData.getDifferentGqGroup(gqGroup);
		ElGamalMultiRecipientPublicKey otherGroupPublicKey =
				ElGamalMultiRecipientKeyPair.genKeyPair(otherGroup, 1, randomService).getPublicKey();

		assertThrows(IllegalArgumentException.class, () -> getCiphertext(validMessage, validExponent, otherGroupPublicKey));
	}

	@Test
	void testPublicKeyAndExponentFromDifferentGroupsThrows() {
		ZqGroup otherGroup = GroupTestData.getDifferentZqGroup(zqGroup);
		ZqElement otherGroupExponent = ZqElement.create(randomService.genRandomInteger(otherGroup.getQ()), otherGroup);

		assertThrows(IllegalArgumentException.class, () -> getCiphertext(validMessage, otherGroupExponent, validPK));
	}

	@Test
	void testMoreMessageElementsThenPublicKeyElementsThrows() {
		ElGamalMultiRecipientPublicKey tooShortPK =
				ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, NUM_RECIPIENTS - 1, randomService).getPublicKey();

		assertThrows(IllegalArgumentException.class, () -> getCiphertext(validMessage, validExponent, tooShortPK));
	}

	@Test
	void testIdentityRandomnessWithNoCompressionAndIdentityMessageElementsThenGammaIsGeneratorAndCiphertextIsPrivateKey() {
		ZqElement one = ZqElement.create(BigInteger.ONE, zqGroup);
		ElGamalMultiRecipientCiphertext ciphertext = getCiphertext(onesMessage, one, validPK);

		assertEquals(gqGroup.getGenerator(), ciphertext.getGamma());
		assertEquals(validPK.stream().collect(Collectors.toList()), ciphertext.stream().skip(1).collect(Collectors.toList()));
	}

	@Test
	void testFewerMessagesThanKeysWithIdentityRandomnessAndIdentityMessageElementsThenCompression() {
		int nMessages = NUM_RECIPIENTS / 2;
		List<GqElement> oneElements =
				Stream.generate(() -> GqElement.create(BigInteger.ONE, gqGroup)).limit(nMessages).collect(Collectors.toList());
		ElGamalMultiRecipientMessage smallOneMessage = new ElGamalMultiRecipientMessage(oneElements);
		ZqElement oneExponent = ZqElement.create(BigInteger.ONE, zqGroup);
		ElGamalMultiRecipientCiphertext ciphertext = getCiphertext(smallOneMessage, oneExponent, validPK);

		//With a exponent of one and message of ones, the ciphertext phis is just the public key
		assertEquals(validPK.stream().limit(nMessages - 1).collect(Collectors.toList()),
				ciphertext.stream().skip(1).limit(nMessages - 1).collect(Collectors.toList()));

		GqElement compressedKey =
				validPK
						.stream()
						.skip(nMessages - 1)
						.reduce(GqElement::multiply)
						.orElseThrow(() -> new RuntimeException("Should not reach"));
		assertEquals(compressedKey, ciphertext.get(nMessages - 1));
	}

	@Test
	void testZeroExponentGivesMessage() {
		ZqElement zeroExponent = ZqElement.create(BigInteger.ZERO, zqGroup);
		ElGamalMultiRecipientCiphertext ciphertext = getCiphertext(validMessage, zeroExponent, validPK);
		assertEquals(validMessage.stream().collect(Collectors.toList()), ciphertext.stream().skip(1).collect(Collectors.toList()));
		assertEquals(gqIdentity, ciphertext.getGamma());
	}

	@Test
	void testSpecificValues() {
		GqGroup group = new GqGroup(BigInteger.valueOf(11), BigInteger.valueOf(5), BigInteger.valueOf(3));
		ElGamalMultiRecipientMessage message =
				new ElGamalMultiRecipientMessage(
						Arrays.asList(
								GqElement.create(BigInteger.valueOf(4), group),
								GqElement.create(BigInteger.valueOf(5), group)
						)
				);
		ZqElement exponent = ZqElement.create(BigInteger.valueOf(2), ZqGroup.sameOrderAs(group));
		ElGamalMultiRecipientPublicKey publicKey =
				new ElGamalMultiRecipientPublicKey(
						Arrays.asList(
								GqElement.create(BigInteger.valueOf(5), group),
								GqElement.create(BigInteger.valueOf(9), group)
						)
				);
		ElGamalMultiRecipientCiphertext ciphertext =
				ElGamalMultiRecipientCiphertext.create(
						GqElement.create(BigInteger.valueOf(9), group),
						Arrays.asList(
								GqElement.create(BigInteger.ONE, group),
								GqElement.create(BigInteger.valueOf(9), group)
						)
				);

		assertEquals(ciphertext, getCiphertext(message, exponent, publicKey));
	}

	// Provides parameters for the testGetCiphertextWithRealValues.
	static Stream<Arguments> jsonFileArgumentProvider() {

		final List<TestParameters> parametersList = TestParameters.fromResource("/elgamal/get-ciphertext.json");

		return parametersList.stream().parallel().map(testParameters -> {
			// Context.
			final JsonData context = testParameters.getContext();
			final BigInteger p = context.get("p", BigInteger.class);
			final BigInteger q = context.get("q", BigInteger.class);
			final BigInteger g = context.get("g", BigInteger.class);

			final GqGroup gqGroup = new GqGroup(p, q, g);
			final ZqGroup zqGroup = new ZqGroup(q);

			// Parse first message parameters.
			final JsonData input = testParameters.getInput();

			final BigInteger[] boldM = input.get("bold_m", BigInteger[].class);
			final List<GqElement> message = Arrays.stream(boldM).map(m -> GqElement.create(m, gqGroup)).collect(Collectors.toList());

			// Parse random exponent.
			final BigInteger r = input.get("r", BigInteger.class);
			ZqElement exponent = ZqElement.create(r, zqGroup);

			// Parse public key.
			final BigInteger[] boldPk = input.get("bold_pk", BigInteger[].class);
			final List<GqElement> publicKey = Arrays.stream(boldPk).map(pk -> GqElement.create(pk, gqGroup)).collect(Collectors.toList());

			// Parse resulting ciphertext.
			final JsonData outputJsonData = testParameters.getOutput();

			final GqElement gammaRes = GqElement.create(outputJsonData.get("gamma", BigInteger.class), gqGroup);
			final BigInteger[] phisOutput = outputJsonData.get("phis", BigInteger[].class);
			final List<GqElement> phisRes = Arrays.stream(phisOutput).map(phi -> GqElement.create(phi, gqGroup)).collect(Collectors.toList());

			return Arguments.of(message, exponent, publicKey, gammaRes, phisRes, testParameters.getDescription());
		});
	}

	@ParameterizedTest
	@MethodSource("jsonFileArgumentProvider")
	@DisplayName("with a valid other ciphertext gives expected result")
	void testGetCiphertextWithRealValues(final List<GqElement> messageList, final ZqElement exponent, List<GqElement> publicKeyList,
			final GqElement gammaRes, final List<GqElement> phisRes, final String description) {

		// Create first ciphertext.
		final ElGamalMultiRecipientMessage message = new ElGamalMultiRecipientMessage(messageList);

		// Create second ciphertext.
		final ElGamalMultiRecipientPublicKey publicKey = new ElGamalMultiRecipientPublicKey(publicKeyList);

		// Expected multiplication result.
		final ElGamalMultiRecipientCiphertext ciphertextRes = ElGamalMultiRecipientCiphertext.create(gammaRes, phisRes);

		assertEquals(ciphertextRes, ElGamalMultiRecipientCiphertext.getCiphertext(message, exponent, publicKey),
				String.format("assertion failed for: %s", description));
	}
}
