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

import java.math.BigInteger;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;

class ElGamalMultiRecipientEncryptionDecryptionTest {

	private static final int NUM_ELEMENTS = 10;

	private static RandomService randomService;
	private static GqGroup gqGroup;
	private static GqGroupGenerator generator;
	private static ZqGroup zqGroup;

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
		List<GqElement> validMessageElements = Stream.generate(generator::genMember).limit(NUM_ELEMENTS).collect(Collectors.toList());
		message = new ElGamalMultiRecipientMessage(validMessageElements);
	}

	@RepeatedTest(10)
	void testEncryptAndDecryptGivesOriginalMessage() {
		final ElGamalMultiRecipientKeyPair keyPair = ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, NUM_ELEMENTS, randomService);
		final ZqElement exponent = ZqElement.create(randomService.genRandomInteger(zqGroup.getQ()), zqGroup);
		final ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertext.getCiphertext(message, exponent, keyPair.getPublicKey());
		final ElGamalMultiRecipientMessage decryptedMessage = ElGamalMultiRecipientMessage.getMessage(ciphertext, keyPair.getPrivateKey());

		assertEquals(message, decryptedMessage);
	}

	@RepeatedTest(10)
	void testEncryptAndDecryptWithLongerKeysGivesOriginalMessage() {
		final ElGamalMultiRecipientKeyPair keyPair = ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, NUM_ELEMENTS + 1, randomService);
		final ZqElement exponent = ZqElement.create(randomService.genRandomInteger(zqGroup.getQ()), zqGroup);
		final ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertext.getCiphertext(message, exponent, keyPair.getPublicKey());
		final ElGamalMultiRecipientMessage decryptedMessage = ElGamalMultiRecipientMessage.getMessage(ciphertext, keyPair.getPrivateKey());

		assertEquals(message, decryptedMessage);
	}

	@Test
	void testEncryptAndDecryptWithDifferentKeysGivesDifferentMessage() {
		final ElGamalMultiRecipientKeyPair keyPair = ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, NUM_ELEMENTS, randomService);
		final ZqElement exponent = genNonZeroExponent(gqGroup.getQ());
		final ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertext.getCiphertext(message, exponent, keyPair.getPublicKey());
		ElGamalMultiRecipientKeyPair differentKeyPair;
		do {
			differentKeyPair = ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, NUM_ELEMENTS, randomService);
		} while (differentKeyPair.equals(keyPair));
		final ElGamalMultiRecipientMessage differentMessage = ElGamalMultiRecipientMessage.getMessage(ciphertext, differentKeyPair.getPrivateKey());

		assertNotEquals(message, differentMessage);
	}

	@Test
	void testEncryptAndDecryptWithDifferentLongerKeysGivesDifferentMessage() {
		final ElGamalMultiRecipientKeyPair keyPair = ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, NUM_ELEMENTS + 1, randomService);
		final ZqElement exponent = genNonZeroExponent(gqGroup.getQ());
		final ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertext.getCiphertext(message, exponent, keyPair.getPublicKey());
		ElGamalMultiRecipientKeyPair differentKeyPair;
		do {
			differentKeyPair = ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, NUM_ELEMENTS + 1, randomService);
		} while (differentKeyPair.equals(keyPair));
		final ElGamalMultiRecipientMessage differentMessage = ElGamalMultiRecipientMessage.getMessage(ciphertext, differentKeyPair.getPrivateKey());

		assertNotEquals(message, differentMessage);
	}

	@Test
	void testEncryptAndDecryptWithDifferentKeySizesGivesSameMessage() {
		final ElGamalMultiRecipientKeyPair keyPair = ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, NUM_ELEMENTS, randomService);
		final ZqElement exponent = genNonZeroExponent(gqGroup.getQ());
		final ElGamalMultiRecipientPublicKey publicKey = keyPair.getPublicKey();
		final ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertext.getCiphertext(message, exponent, publicKey);
		final List<ZqElement> privateKeyElements = keyPair.getPrivateKey().stream().collect(Collectors.toList());
		privateKeyElements.add(genNonZeroExponent(gqGroup.getQ()));
		final ElGamalMultiRecipientPrivateKey longerPrivateKey = new ElGamalMultiRecipientPrivateKey(privateKeyElements);
		final ElGamalMultiRecipientMessage otherMessage = ElGamalMultiRecipientMessage.getMessage(ciphertext, longerPrivateKey);

		assertEquals(message, otherMessage);
	}

	private ZqElement genNonZeroExponent(BigInteger q) {
		final ZqGroup group = new ZqGroup(q);
		final BigInteger qMinusOne = q.subtract(BigInteger.ONE);
		final BigInteger random = randomService.genRandomInteger(qMinusOne).add(BigInteger.ONE);
		return ZqElement.create(random, group);
	}
}
