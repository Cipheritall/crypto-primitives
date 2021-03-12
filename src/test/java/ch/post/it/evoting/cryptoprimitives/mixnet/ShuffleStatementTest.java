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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.SecureRandom;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;

@DisplayName("A ShuffleStatement")
class ShuffleStatementTest extends TestGroupSetup {

	private static final int KEY_ELEMENTS_NUMBER = 11;
	private static final SecureRandom secureRandom = new SecureRandom();

	private static ElGamalMultiRecipientPublicKey publicKey;
	private static ElGamalGenerator elGamalGenerator;

	private int n;
	private int l;
	private SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts;
	private SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> shuffledCiphertexts;

	@BeforeAll
	static void setUpAll() {
		elGamalGenerator = new ElGamalGenerator(gqGroup);

		publicKey = elGamalGenerator.genRandomPublicKey(KEY_ELEMENTS_NUMBER);
	}

	@BeforeEach
	void setUp() {
		n = secureRandom.nextInt(KEY_ELEMENTS_NUMBER - 1) + 1;
		l = secureRandom.nextInt(KEY_ELEMENTS_NUMBER - 1) + 1;

		ciphertexts = SameGroupVector.from(elGamalGenerator.genRandomCiphertexts(publicKey, l, n));
		shuffledCiphertexts = SameGroupVector.from(elGamalGenerator.genRandomCiphertexts(publicKey, l, n));
	}

	@Test
	@DisplayName("with valid parameters gives expected statement")
	void construct() {
		final ShuffleStatement shuffleStatement = new ShuffleStatement(ciphertexts, shuffledCiphertexts);

		assertEquals(gqGroup, shuffleStatement.getCiphertexts().getGroup());
		assertEquals(gqGroup, shuffleStatement.getShuffledCiphertexts().getGroup());
	}

	@Test
	@DisplayName("with any null parameter throws NullPointerException")
	void constructNullParams() {
		assertThrows(NullPointerException.class, () -> new ShuffleStatement(null, shuffledCiphertexts));
		assertThrows(NullPointerException.class, () -> new ShuffleStatement(ciphertexts, null));
	}

	@Test
	@DisplayName("with empty ciphertexts throws IllegalArgumentException")
	void constructEmptyParams() {
		final SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> emptyCiphertexts = SameGroupVector.of();
		final SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> emptyShuffledCiphertexts = SameGroupVector.of();

		final IllegalArgumentException emptyCiphertextsException = assertThrows(IllegalArgumentException.class,
				() -> new ShuffleStatement(emptyCiphertexts, shuffledCiphertexts));
		assertEquals("The ciphertexts vector can not be empty.", emptyCiphertextsException.getMessage());

		final IllegalArgumentException emptyShuffledCiphertextsException = assertThrows(IllegalArgumentException.class,
				() -> new ShuffleStatement(ciphertexts, emptyShuffledCiphertexts));
		assertEquals("The shuffled ciphertexts vector can not be empty.", emptyShuffledCiphertextsException.getMessage());
	}

	@Test
	@DisplayName("with ciphertexts and shuffled ciphertexts of different size throws IllegalArgumentException")
	void constructDiffSizeVectors() {
		final SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> longerCiphertexts = ciphertexts
				.append(elGamalGenerator.genRandomCiphertext(l));

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ShuffleStatement(longerCiphertexts, shuffledCiphertexts));
		assertEquals("The ciphertexts and shuffled ciphertexts vectors must have the same size.", exception.getMessage());
	}

	@Test
	@DisplayName("with ciphertexts and shuffled ciphertexts having different size throws IllegalArgumentException")
	void constructCiphertextsAndShuffledDiffSizePhis() {
		final SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> morePhisCiphertexts = elGamalGenerator.genRandomCiphertextVector(n, l + 1);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ShuffleStatement(morePhisCiphertexts, shuffledCiphertexts));
		assertEquals("The ciphertexts and shuffled ciphertexts must have the same size.", exception.getMessage());
	}

	@Test
	@DisplayName("with ciphertexts and shuffled ciphertexts from different groups throws IllegalArgumentException")
	void constructDiffGroupCiphertextsAndShuffled() {
		// Ciphertexts from different group.
		final ElGamalGenerator differentElGamalGenerator = new ElGamalGenerator(otherGqGroup);
		final SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> diffGroupCiphertexts = differentElGamalGenerator
				.genRandomCiphertextVector(n, l);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ShuffleStatement(diffGroupCiphertexts, shuffledCiphertexts));
		assertEquals("The ciphertexts and shuffled ciphertexts must be part of the same group.", exception.getMessage());
	}

	@Test
	void testEquals() {
		final ShuffleStatement shuffleStatement1 = new ShuffleStatement(ciphertexts, shuffledCiphertexts);
		final ShuffleStatement shuffleStatement2 = new ShuffleStatement(ciphertexts, shuffledCiphertexts);

		final SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> otherCiphertexts = ciphertexts
				.append(elGamalGenerator.genRandomCiphertext(l));
		final SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> otherShuffledCiphertexts = shuffledCiphertexts
				.append(elGamalGenerator.genRandomCiphertext(l));
		final ShuffleStatement shuffleStatement3 = new ShuffleStatement(otherCiphertexts, otherShuffledCiphertexts);

		assertEquals(shuffleStatement1, shuffleStatement1);
		assertEquals(shuffleStatement1, shuffleStatement2);
		assertNotEquals(shuffleStatement1, shuffleStatement3);
	}

	@Test
	void testHashCode() {
		final ShuffleStatement shuffleStatement1 = new ShuffleStatement(ciphertexts, shuffledCiphertexts);
		final ShuffleStatement shuffleStatement2 = new ShuffleStatement(ciphertexts, shuffledCiphertexts);

		assertEquals(shuffleStatement1, shuffleStatement2);
		assertEquals(shuffleStatement1.hashCode(), shuffleStatement1.hashCode());
		assertEquals(shuffleStatement1.hashCode(), shuffleStatement2.hashCode());
	}
}
