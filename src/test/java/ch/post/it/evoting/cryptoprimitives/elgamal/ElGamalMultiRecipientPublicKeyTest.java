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

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.SecureRandom;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.test.tools.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;

@DisplayName("A multi-recipient public key")
class ElGamalMultiRecipientPublicKeyTest extends TestGroupSetup {

	private static ElGamalGenerator elGamalGenerator;

	@BeforeAll
	static void setUpAll() {
		elGamalGenerator = new ElGamalGenerator(gqGroup);
	}

	// Provides parameters for the withInvalidParameters test.
	static Stream<Arguments> createInvalidArgumentsProvider() {
		List<GqElement> keyElementsFirstNull = new LinkedList<>();
		keyElementsFirstNull.add(null);
		keyElementsFirstNull.add(gqGroupGenerator.genMember());

		List<GqElement> keyElementsSecondNull = new LinkedList<>();
		keyElementsSecondNull.add(gqGroupGenerator.genMember());
		keyElementsSecondNull.add(null);

		List<GqElement> keyElementsDifferentGroups = new LinkedList<>();
		keyElementsDifferentGroups.add(gqGroupGenerator.genMember());
		keyElementsDifferentGroups.add(otherGqGroupGenerator.genMember());

		return Stream.of(
				Arguments.of(null, NullPointerException.class, null),
				Arguments.of(Collections.EMPTY_LIST, IllegalArgumentException.class, "An ElGamal public key must not be empty."),
				Arguments.of(keyElementsFirstNull, IllegalArgumentException.class, "Elements must not contain nulls"),
				Arguments.of(keyElementsSecondNull, IllegalArgumentException.class, "Elements must not contain nulls"),
				Arguments.of(keyElementsDifferentGroups, IllegalArgumentException.class, "All elements must belong to the same group.")
		);
	}

	@ParameterizedTest(name = "key = {0} throws {1}")
	@MethodSource("createInvalidArgumentsProvider")
	@DisplayName("created with invalid parameters")
	void constructionWithInvalidParametersTest(
			List<GqElement> keyElements, final Class<? extends RuntimeException> exceptionClass, String errorMsg) {
		Exception exception = assertThrows(exceptionClass, () -> new ElGamalMultiRecipientPublicKey(keyElements));
		assertEquals(errorMsg, exception.getMessage());
	}

	@Nested
	@DisplayName("calling compress with")
	class CompressTest {

		private static final int PUBLIC_KEY_SIZE = 10;

		private final SecureRandom secureRandom = new SecureRandom();

		private ElGamalMultiRecipientPublicKey elGamalMultiRecipientPublicKey;
		private int length;

		@BeforeEach
		void setUpEach() {
			elGamalMultiRecipientPublicKey = elGamalGenerator.genRandomPublicKey(PUBLIC_KEY_SIZE);
			length = secureRandom.nextInt(PUBLIC_KEY_SIZE) + 1;
		}

		@Test
		@DisplayName("any non positive length throws an IllegalArgumentException.")
		void compressParameterShouldBePositive() {
			final IllegalArgumentException illegalArgumentException0 =
					assertThrows(IllegalArgumentException.class, () -> elGamalMultiRecipientPublicKey.compress(-1));

			assertEquals("The requested length for key compression must be strictly positive.", illegalArgumentException0.getMessage());

			final IllegalArgumentException illegalArgumentException1 =
					assertThrows(IllegalArgumentException.class, () -> elGamalMultiRecipientPublicKey.compress(0));

			assertEquals("The requested length for key compression must be strictly positive.", illegalArgumentException1.getMessage());
		}

		@Test
		@DisplayName("any length greater than the public key size throws an IllegalArgumentException.")
		void compressParameterShouldAtMostPublicKeySize() {
			final IllegalArgumentException illegalArgumentException =
					assertThrows(IllegalArgumentException.class, () -> elGamalMultiRecipientPublicKey.compress(PUBLIC_KEY_SIZE + 1));

			assertEquals("The requested length for key compression must be at most the public key size.", illegalArgumentException.getMessage());
		}

		@Test
		@DisplayName("a length of 1 on a public key of size 1 returns a compressed public key of size 1 with the same element as the unique private key element.")
		void compressPublicKeyOfSizeOne() {
			final int length = 1;
			final ElGamalMultiRecipientPublicKey elGamalMultiRecipientPublicKey = elGamalGenerator.genRandomPublicKey(length);
			final ElGamalMultiRecipientPublicKey compressedPublicKey = elGamalMultiRecipientPublicKey.compress(length);

			assertAll(
					() -> assertEquals(length, compressedPublicKey.size()),
					() -> assertEquals(elGamalMultiRecipientPublicKey.get(0), compressedPublicKey.get(0)));
		}

		@Test
		@DisplayName("any valid length returns a compressed public key of size length.")
		void compressWithValidParameterReturnsCompressedOfExpectedSize() {

			final ElGamalMultiRecipientPublicKey compressedPublicKey = elGamalMultiRecipientPublicKey.compress(length);

			assertEquals(length, compressedPublicKey.size());
		}

		@Test
		@DisplayName("any valid length returns a compressed public key with the same first (length - 1) elements as the public key.")
		void compressWithValidParameterReturnsCompressedWithSameFirstLengthMinus1Elements() {

			final ElGamalMultiRecipientPublicKey compressedPublicKey = elGamalMultiRecipientPublicKey.compress(length);

			for (int i = 0; i < length - 1; i++) {
				assertEquals(elGamalMultiRecipientPublicKey.get(i), compressedPublicKey.get(i));
			}
		}

		@Test
		@DisplayName("any valid length returns a compressed public key with a correct compressed last element.")
		void compressWithValidParameterReturnsCompressedWithCorrectElement() {

			final ElGamalMultiRecipientPublicKey compressedPublicKey = elGamalMultiRecipientPublicKey.compress(length);

			final GqElement compressedKeyElement = elGamalMultiRecipientPublicKey.stream()
					.skip(length - 1L)
					.reduce(elGamalMultiRecipientPublicKey.getGroup().getIdentity(), GqElement::multiply);

			assertEquals(compressedKeyElement, compressedPublicKey.get(length - 1));
		}
	}
}
