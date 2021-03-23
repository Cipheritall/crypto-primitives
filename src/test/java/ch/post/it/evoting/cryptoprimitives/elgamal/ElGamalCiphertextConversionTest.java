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

import static ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext.convertMessagesToCiphertexts;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.stream.Collectors;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;

class ElGamalCiphertextConversionTest {

	private static final SecureRandom random = new SecureRandom();

	private GqGroup group;
	private int vectorSize;
	private int messageSize;
	private ElGamalGenerator elGamalGenerator;
	private GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts;
	private GroupVector<ElGamalMultiRecipientMessage, GqGroup> messages;

	@BeforeEach
	void setup() {
		final int maxSize = 10;
		vectorSize = random.nextInt(maxSize) + 1;
		messageSize = random.nextInt(maxSize) + 1;
		group = GroupTestData.getGqGroup();
		elGamalGenerator = new ElGamalGenerator(group);
		ciphertexts = elGamalGenerator.genRandomCiphertextVector(vectorSize, messageSize);
		messages = elGamalGenerator.genRandomMessageVector(vectorSize, messageSize);
	}

	@Test
	@DisplayName("Convert messages with null arguments throws a NullPointerException")
	void convertMessagesToCiphertextsWithNullArguments() {
		assertThrows(NullPointerException.class, () -> convertMessagesToCiphertexts(null, messages));
		assertThrows(NullPointerException.class, () -> convertMessagesToCiphertexts(ciphertexts, null));
	}

	@Test
	@DisplayName("Convert messages from different group than ciphertexts throws an IllegalArgumentException")
	void convertMessagesToCiphertextsWithDifferentGroups() {
		GqGroup otherGroup = GroupTestData.getDifferentGqGroup(group);
		ciphertexts = new ElGamalGenerator(otherGroup).genRandomCiphertextVector(vectorSize, messageSize);
		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> convertMessagesToCiphertexts(ciphertexts, messages));
		assertEquals("The ciphertexts and the messages must have the same group.", exception.getMessage());
	}

	@Test
	@DisplayName("Convert messages of different size than ciphertexts throws an IllegalArgumentException")
	void convertMessagesToCiphertextsDifferentSize() {
		messages = elGamalGenerator.genRandomMessageVector(vectorSize, messageSize + 1);
		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> convertMessagesToCiphertexts(ciphertexts, messages));
		assertEquals("The ciphertexts and the messages must have the same size.", exception.getMessage());
	}

	@Test
	@DisplayName("Convert messages from vector of different size than ciphertext vector throws an IllegalArgumentException")
	void convertMessagesToCiphertextsDifferentVectorSize() {
		messages = elGamalGenerator.genRandomMessageVector(vectorSize + 1, messageSize);
		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> convertMessagesToCiphertexts(ciphertexts, messages));
		assertEquals("The ciphertext vector and the message vector must have the same size.", exception.getMessage());
	}

	@Test
	@DisplayName("Convert messages to ciphertexts yields expected ciphertexts")
	void convertMessagesToCiphertextsTest() {
		GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> convertedMessages = convertMessagesToCiphertexts(ciphertexts, messages);
		for (int i = 0; i < convertedMessages.size(); i++) {
			assertEquals(ciphertexts.get(i).getGamma(), convertedMessages.get(i).getGamma());
			assertEquals(messages.get(i).stream().collect(Collectors.toList()),
					convertedMessages.get(i).stream().skip(1).collect(Collectors.toList()));
		}
	}

	@Test
	@DisplayName("Convert messages to ciphertexts with specific values returns the expected result")
	void convertMessagesToCiphertextsWithSpecificValues() {
		GqGroup group = new GqGroup(BigInteger.valueOf(11), BigInteger.valueOf(5), BigInteger.valueOf(3));

		// Create GqElements
		GqElement one = GqElement.create(BigInteger.ONE, group);
		GqElement three = GqElement.create(BigInteger.valueOf(3), group);
		GqElement four = GqElement.create(BigInteger.valueOf(4), group);
		GqElement five = GqElement.create(BigInteger.valueOf(5), group);
		GqElement nine = GqElement.create(BigInteger.valueOf(9), group);

		ElGamalMultiRecipientCiphertext c0 = ElGamalMultiRecipientCiphertext.create(one, Arrays.asList(three, four));
		ElGamalMultiRecipientCiphertext c1 = ElGamalMultiRecipientCiphertext.create(three, Arrays.asList(four, nine));
		GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts = GroupVector.of(c0, c1);

		ElGamalMultiRecipientMessage m0 = new ElGamalMultiRecipientMessage(Arrays.asList(four, five));
		ElGamalMultiRecipientMessage m1 = new ElGamalMultiRecipientMessage(Arrays.asList(one, five));
		GroupVector<ElGamalMultiRecipientMessage, GqGroup> messages = GroupVector.of(m0, m1);

		ElGamalMultiRecipientCiphertext expectedC0 = ElGamalMultiRecipientCiphertext.create(one, Arrays.asList(four, five));
		ElGamalMultiRecipientCiphertext expectedC1 = ElGamalMultiRecipientCiphertext.create(three, Arrays.asList(one, five));
		GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> expectedCiphertexts = GroupVector.of(expectedC0, expectedC1);

		assertEquals(expectedCiphertexts, convertMessagesToCiphertexts(ciphertexts, messages));
	}
}
