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

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
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

import ch.post.it.evoting.cryptoprimitives.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;

@DisplayName("A multi-recipient secret key")
class ElGamalMultiRecipientPrivateKeyTest extends TestGroupSetup {

	private static ZqElement zqElement;
	private static ElGamalGenerator elGamalGenerator;

	@BeforeAll
	static void setUp() {
		zqElement = zqGroupGenerator.genRandomZqElementMember();
		elGamalGenerator = new ElGamalGenerator(gqGroup);
	}

	@Test
	void givenAnExponentOfZeroThenThrows() {
		ZqElement zeroExponent = ZqElement.create(BigInteger.ZERO, zqGroup);
		List<ZqElement> exponents = Arrays.asList(zqElement, zeroExponent);
		assertThrows(IllegalArgumentException.class, () -> new ElGamalMultiRecipientPrivateKey(exponents));
	}

	@Test
	void givenAnExponentOfOneThenThrows() {
		ZqElement oneExponent = ZqElement.create(BigInteger.ONE, zqGroup);
		List<ZqElement> exponents = Arrays.asList(zqElement, oneExponent);
		assertThrows(IllegalArgumentException.class, () -> new ElGamalMultiRecipientPrivateKey(exponents));
	}

	// Provides parameters for the withInvalidParameters test.
	static Stream<Arguments> createInvalidArgumentsProvider() {
		List<ZqElement> messageElementsFirstNull = new LinkedList<>();
		messageElementsFirstNull.add(null);
		messageElementsFirstNull.add(zqGroupGenerator.genRandomZqElementMember());

		List<ZqElement> messageElementsSecondNull = new LinkedList<>();
		messageElementsSecondNull.add(zqGroupGenerator.genRandomZqElementMember());
		messageElementsSecondNull.add(null);

		List<ZqElement> messageElementsDifferentGroups = new LinkedList<>();
		messageElementsDifferentGroups.add(zqGroupGenerator.genRandomZqElementMember());
		messageElementsDifferentGroups.add(otherZqGroupGenerator.genRandomZqElementMember());

		return Stream.of(
				Arguments.of(null, NullPointerException.class, null),
				Arguments.of(Collections.EMPTY_LIST, IllegalArgumentException.class, "An ElGamal private key cannot be empty."),
				Arguments.of(messageElementsFirstNull, IllegalArgumentException.class, "Elements must not contain nulls"),
				Arguments.of(messageElementsSecondNull, IllegalArgumentException.class, "Elements must not contain nulls"),
				Arguments.of(messageElementsDifferentGroups, IllegalArgumentException.class, "All elements must belong to the same group.")
		);
	}

	@ParameterizedTest(name = "message = {0} throws {1}")
	@MethodSource("createInvalidArgumentsProvider")
	@DisplayName("created with invalid parameters")
	void constructionWithInvalidParametersTest(
			List<ZqElement> messageElements, final Class<? extends RuntimeException> exceptionClass, String errorMsg) {
		final Exception exception = assertThrows(exceptionClass, () -> new ElGamalMultiRecipientPrivateKey(messageElements));
		assertEquals(errorMsg, exception.getMessage());
	}

	@Nested
	@DisplayName("calling compress with")
	class CompressTest {

		private static final int PRIVATE_KEY_SIZE = 10;

		private final SecureRandom secureRandom = new SecureRandom();

		private ElGamalMultiRecipientPrivateKey elGamalMultiRecipientPrivateKey;
		private int length;

		@BeforeEach
		void setUpEach() {
			elGamalMultiRecipientPrivateKey = elGamalGenerator.genRandomPrivateKey(PRIVATE_KEY_SIZE);
			length = secureRandom.nextInt(PRIVATE_KEY_SIZE) + 1;
		}

		@Test
		@DisplayName("any non positive length throws an IllegalArgumentException.")
		void compressParameterShouldBePositive() {
			final IllegalArgumentException illegalArgumentException0 =
					assertThrows(IllegalArgumentException.class, () -> elGamalMultiRecipientPrivateKey.compress(-1));

			assertEquals("The requested length for key compression must be strictly positive.", illegalArgumentException0.getMessage());

			final IllegalArgumentException illegalArgumentException1 =
					assertThrows(IllegalArgumentException.class, () -> elGamalMultiRecipientPrivateKey.compress(0));

			assertEquals("The requested length for key compression must be strictly positive.", illegalArgumentException1.getMessage());
		}

		@Test
		@DisplayName("any length greater than the private key size throws an IllegalArgumentException.")
		void compressParameterShouldAtMostPrivateKeySize() {
			final IllegalArgumentException illegalArgumentException =
					assertThrows(IllegalArgumentException.class, () -> elGamalMultiRecipientPrivateKey.compress(PRIVATE_KEY_SIZE + 1));

			assertEquals("The requested length for key compression must be at most the secret key size.", illegalArgumentException.getMessage());
		}

		@Test
		@DisplayName("a length of 1 on a private key of size 1 returns a vector of size 1 with the same element as the unique private key element.")
		void compressPrivateKeyOfSizeOne() {
			final int length = 1;
			final ElGamalMultiRecipientPrivateKey elGamalMultiRecipientPrivateKey = elGamalGenerator.genRandomPrivateKey(length);
			final List<ZqElement> vector = elGamalMultiRecipientPrivateKey.compress(length);

			assertAll(
					() -> assertEquals(length, vector.size()),
					() -> assertEquals(elGamalMultiRecipientPrivateKey.get(0), vector.get(0)));
		}

		@Test
		@DisplayName("any valid length returns a vector of size length.")
		void compressWithValidParameterReturnsCompressedOfExpectedSize() {

			final List<ZqElement> vector = elGamalMultiRecipientPrivateKey.compress(length);

			assertEquals(length, vector.size());
		}

		@Test
		@DisplayName("any valid length returns a vector with the same first (length - 1) elements as the private key.")
		void compressWithValidParameterReturnsCompressedWithSameFirstLengthMinus1Elements() {

			final List<ZqElement> vector = elGamalMultiRecipientPrivateKey.compress(length);

			for (int i = 0; i < length - 1; i++) {
				assertEquals(elGamalMultiRecipientPrivateKey.get(i), vector.get(i));
			}
		}

		@Test
		@DisplayName("any valid length returns a vector with a correct compressed last element.")
		void compressWithValidParameterReturnsCompressedWithCorrectElement() {

			final List<ZqElement> vector = elGamalMultiRecipientPrivateKey.compress(length);

			final ZqElement compressedKeyElement = elGamalMultiRecipientPrivateKey.stream()
					.skip(length - 1L)
					.reduce(elGamalMultiRecipientPrivateKey.getGroup().getIdentity(), ZqElement::add);

			assertEquals(compressedKeyElement, vector.get(length - 1));
		}
	}
}
