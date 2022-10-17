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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.SecureRandom;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import ch.post.it.evoting.cryptoprimitives.internal.elgamal.ElGamalMultiRecipientCiphertexts;
import ch.post.it.evoting.cryptoprimitives.internal.elgamal.ElGamalMultiRecipientMessages;
import ch.post.it.evoting.cryptoprimitives.internal.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;

class ElGamalMultiRecipientMessageTest {

	private static final int NUM_ELEMENTS = 2;

	private static RandomService randomService;
	private static GqGroup gqGroup;
	private static GqGroupGenerator generator;
	private static ZqGroup zqGroup;

	private static GroupVector<GqElement, GqGroup> validMessageElements;
	private static ElGamalMultiRecipientMessage message;

	@BeforeAll
	static void setUpAll() {
		randomService = new RandomService();
		gqGroup = GroupTestData.getGqGroup();
		zqGroup = ZqGroup.sameOrderAs(gqGroup);
		generator = new GqGroupGenerator(gqGroup);
	}

	@BeforeEach
	void setUp() {
		GqElement m1 = generator.genMember();
		GqElement m2 = generator.genMember();

		validMessageElements = GroupVector.of(m1, m2);
		message = new ElGamalMultiRecipientMessage(validMessageElements);
	}

	@Test
	@DisplayName("contains the correct message")
	void constructionTest() {
		ElGamalMultiRecipientMessage message = new ElGamalMultiRecipientMessage(validMessageElements);

		assertEquals(validMessageElements, message.stream().collect(GroupVector.toGroupVector()));
	}

	// Provides parameters for the withInvalidParameters test.
	static Stream<Arguments> createInvalidArgumentsProvider() {
		return Stream.of(
				Arguments.of(null, NullPointerException.class, null),
				Arguments.of(GroupVector.of(), IllegalArgumentException.class, "An ElGamal message must not be empty.")
		);
	}

	@ParameterizedTest(name = "message = {0} throws {1}")
	@MethodSource("createInvalidArgumentsProvider")
	@DisplayName("created with invalid parameters")
	void constructionWithInvalidParametersTest(
			final GroupVector<GqElement, GqGroup> messageElements, final Class<? extends RuntimeException> exceptionClass, String errorMsg) {
		Exception exception = assertThrows(exceptionClass, () -> new ElGamalMultiRecipientMessage(messageElements));
		assertEquals(errorMsg, exception.getMessage());
	}

	@Test
	@DisplayName("create from ones contains only 1s")
	void onesTest() {
		int n = new SecureRandom().nextInt(10) + 1;
		ElGamalMultiRecipientMessage ones = ElGamalMultiRecipientMessages.ones(gqGroup, n);

		List<GqElement> onesList = Stream.generate(gqGroup::getIdentity).limit(n).collect(Collectors.toList());

		assertEquals(onesList, ones.stream().collect(Collectors.toList()));
		assertEquals(n, ones.size());
	}

	@Test
	@DisplayName("create from ones with bad input throws")
	void onesWithBadInputTest() {
		assertThrows(NullPointerException.class, () -> ElGamalMultiRecipientMessages.ones(null, 1));
		Exception exception = assertThrows(IllegalArgumentException.class, () -> ElGamalMultiRecipientMessages.ones(gqGroup, 0));
		assertEquals("Cannot generate a message of constants of non positive length.", exception.getMessage());
	}

	@Test
	@DisplayName("create from constant contains only constant")
	void constantsTest() {
		int n = new SecureRandom().nextInt(10) + 1;
		GqElement constant = generator.genMember();
		ElGamalMultiRecipientMessage constants = ElGamalMultiRecipientMessages.constantMessage(constant, n);

		List<GqElement> constantsList = Stream.generate(() -> constant).limit(n).collect(Collectors.toList());

		assertEquals(constantsList, constants.stream().collect(Collectors.toList()));
		assertEquals(n, constants.size());
	}

	@Test
	@DisplayName("create from constant with bad input throws")
	void constantsWithBadInputTest() {
		assertThrows(NullPointerException.class, () -> ElGamalMultiRecipientMessages.constantMessage(null, 1));
		GqElement constant = generator.genMember();
		Exception exception =
				assertThrows(IllegalArgumentException.class, () -> ElGamalMultiRecipientMessages.constantMessage(constant, 0));
		assertEquals("Cannot generate a message of constants of non positive length.", exception.getMessage());
	}

	// Provides parameters for the invalid decryption parameters test.
	static Stream<Arguments> createInvalidDecryptionArgumentsProvider() {
		ElGamalMultiRecipientKeyPair keyPair = ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, NUM_ELEMENTS, randomService);
		ElGamalMultiRecipientPrivateKey secretKey = keyPair.getPrivateKey();
		ElGamalMultiRecipientPrivateKey tooShortSecretKey = new ElGamalMultiRecipientPrivateKey(GroupVector.of(secretKey.get(0)));
		ZqElement exponent = ZqElement.create(randomService.genRandomInteger(zqGroup.getQ()), zqGroup);
		ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertexts.getCiphertext(message, exponent, keyPair.getPublicKey());

		GqGroup differentGroup = GroupTestData.getDifferentGqGroup(gqGroup);
		ElGamalMultiRecipientKeyPair differentGroupKeyPair = ElGamalMultiRecipientKeyPair.genKeyPair(differentGroup, NUM_ELEMENTS, randomService);
		ElGamalMultiRecipientPrivateKey differentGroupSecretKey = differentGroupKeyPair.getPrivateKey();

		return Stream.of(
				Arguments.of(null, secretKey, NullPointerException.class),
				Arguments.of(ciphertext, null, NullPointerException.class),
				Arguments.of(ciphertext, tooShortSecretKey, IllegalArgumentException.class),
				Arguments.of(ciphertext, differentGroupSecretKey, IllegalArgumentException.class)
		);
	}

	@ParameterizedTest(name = "ciphertext = {0} and secret key = {1} throws {2}")
	@MethodSource("createInvalidDecryptionArgumentsProvider")
	@DisplayName("get message with invalid parameters")
	void whenGetMessageWithInvalidParametersTest(ElGamalMultiRecipientCiphertext c, ElGamalMultiRecipientPrivateKey sk,
			final Class<? extends RuntimeException> exceptionClass) {
		assertThrows(exceptionClass, () -> ElGamalMultiRecipientMessages.getMessage(c, sk));
	}

	@RepeatedTest(10)
	void testMessageDifferentFromCiphertext() {
		ElGamalMultiRecipientKeyPair keyPair = ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, NUM_ELEMENTS, randomService);
		ZqElement exponent = ZqElement.create(randomService.genRandomInteger(zqGroup.getQ()), zqGroup);
		ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertexts.getCiphertext(message, exponent, keyPair.getPublicKey());
		ElGamalMultiRecipientMessage newMessage = ElGamalMultiRecipientMessages.getMessage(ciphertext, keyPair.getPrivateKey());

		assertNotEquals(ciphertext.stream(), newMessage.stream());
	}

	@Test
	void whenGetMessageFromUnityCiphertextTest() {
		ElGamalMultiRecipientMessage onesMessage = ElGamalMultiRecipientMessages.ones(gqGroup, 2);
		ElGamalMultiRecipientKeyPair keyPair = ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, NUM_ELEMENTS, randomService);
		ZqElement zero = zqGroup.getIdentity();
		ElGamalMultiRecipientCiphertext unityCiphertext = ElGamalMultiRecipientCiphertexts.getCiphertext(onesMessage, zero, keyPair.getPublicKey());
		assertEquals(onesMessage, ElGamalMultiRecipientMessages.getMessage(unityCiphertext, keyPair.getPrivateKey()));
	}
}
