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
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.SecureRandom;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.test.tools.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;

@DisplayName("A VerifiableShuffle constructed with")
class VerifiableShuffleTest extends TestGroupSetup {

	private static final SecureRandom random = new SecureRandom();
	private static final int MAX_NUMBER_CIPHERTEXTS = 10;
	private static final int MAX_CIPHERTEXT_LENGTH = 5;

	private int numCiphertexts;
	private int l;
	private ElGamalGenerator elGamalGenerator;
	private GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts;
	private ShuffleArgument shuffleArgument;

	@BeforeEach
	void setUp() {
		numCiphertexts = random.nextInt(MAX_NUMBER_CIPHERTEXTS) + 2;
		final int[] matrixDimensions = MatrixUtils.getMatrixDimensions(numCiphertexts);
		final int m = matrixDimensions[0];
		final int n = matrixDimensions[1];
		l = random.nextInt(MAX_CIPHERTEXT_LENGTH) + 1;

		elGamalGenerator = new ElGamalGenerator(gqGroup);

		ciphertexts = elGamalGenerator.genRandomCiphertextVector(numCiphertexts, l);
		shuffleArgument = new TestArgumentGenerator(gqGroup).genShuffleArgument(m, n, l);
	}

	@Test
	@DisplayName("valid parameters does not throw")
	void constructWithValidParams() {
		assertDoesNotThrow(() -> new VerifiableShuffle(ciphertexts, shuffleArgument));
	}

	@Test
	@DisplayName("any null parameter throws NullPointerException")
	void constructNullParams() {
		assertThrows(NullPointerException.class, () -> new VerifiableShuffle(null, shuffleArgument));
		assertThrows(NullPointerException.class, () -> new VerifiableShuffle(ciphertexts, null));
	}

	@Test
	@DisplayName("shuffled ciphertexts vector size different from n*m throws IllegalArgumentException")
	void constructShuffledCiphertextsVectorDifferentSize() {
		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> longerCiphertextsVector = elGamalGenerator
				.genRandomCiphertextVector(numCiphertexts + 1, l);

		final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> new VerifiableShuffle(longerCiphertextsVector, shuffleArgument));
		assertEquals("Shuffle ciphertext vector's size must be N = n * m.", illegalArgumentException.getMessage());
	}

	@Test
	@DisplayName("shuffle ciphertexts elements size different from shuffle argument dimension l throws IllegalArgumentException")
	void constructShuffleCiphertextsElementsSizeDifferentThanLDimension() {
		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> longerCiphertextsElements = elGamalGenerator
				.genRandomCiphertextVector(numCiphertexts, l + 1);

		final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> new VerifiableShuffle(longerCiphertextsElements, shuffleArgument));
		assertEquals("Shuffled ciphertexts elements size must be dimension l of shuffle argument.", illegalArgumentException.getMessage());
	}

	@Test
	@DisplayName("shuffled ciphertexts vector and shuffle argument from different group throws IllegalArgumentException")
	void constructShuffleCiphertextsShuffleArgumentDifferentGroup() {
		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> otherGroupCiphertextsVector = new ElGamalGenerator(otherGqGroup)
				.genRandomCiphertextVector(numCiphertexts, l);

		final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> new VerifiableShuffle(otherGroupCiphertextsVector, shuffleArgument));
		assertEquals("Shuffled ciphertext vector and shuffle argument must have the same group.", illegalArgumentException.getMessage());
	}

}
