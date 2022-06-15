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
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullSource;

import ch.post.it.evoting.cryptoprimitives.internal.elgamal.ElGamalMultiRecipientKeyPairs;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.test.tools.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;

@DisplayName("A multi-recipient secret key")
class ElGamalMultiRecipientPrivateKeyTest extends TestGroupSetup {

	private static ElGamalGenerator elGamalGenerator;

	@BeforeAll
	static void setUp() {
		elGamalGenerator = new ElGamalGenerator(gqGroup);
	}

	// Provides parameters for the withInvalidParameters test.
	static Stream<Arguments> createInvalidArgumentsProvider() {
		final List<ZqElement> messageElementsFirstNull = new LinkedList<>();
		messageElementsFirstNull.add(null);
		messageElementsFirstNull.add(zqGroupGenerator.genRandomZqElementMember());

		final List<ZqElement> messageElementsSecondNull = new LinkedList<>();
		messageElementsSecondNull.add(zqGroupGenerator.genRandomZqElementMember());
		messageElementsSecondNull.add(null);

		final List<ZqElement> messageElementsDifferentGroups = new LinkedList<>();
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
			final List<ZqElement> messageElements, final Class<? extends RuntimeException> exceptionClass, final String errorMsg) {
		final Exception exception = assertThrows(exceptionClass, () -> new ElGamalMultiRecipientPrivateKey(messageElements));
		assertEquals(errorMsg, exception.getMessage());
	}

	@Nested
	@DisplayName("calling derivePublicKey")
	class DerivePublicKey {

		private static final int PRIVATE_KEY_SIZE = 10;

		private ElGamalMultiRecipientPrivateKey elGamalMultiRecipientPrivateKey;

		@BeforeEach
		void setUpEach() {
			elGamalMultiRecipientPrivateKey = elGamalGenerator.genRandomPrivateKey(PRIVATE_KEY_SIZE);
		}

		@ParameterizedTest(name = "generator is {0}.")
		@NullSource
		@DisplayName("with a null generator throws a NullPointerException.")
		void nullCheckTest(final GqElement nullGenerator) {
			assertThrows(NullPointerException.class, () -> ElGamalMultiRecipientKeyPairs.derivePublicKey(elGamalMultiRecipientPrivateKey,
					nullGenerator));
		}

		@Test
		@DisplayName("with a generator of different group order throws an IllegalArgumentException.")
		void differentGroupOrderTest() {
			final GqElement generatorFromDifferentGroup = GroupTestData.getDifferentGqGroup(gqGroup).getGenerator();

			final IllegalArgumentException illegalArgumentException =
					assertThrows(IllegalArgumentException.class, () -> ElGamalMultiRecipientKeyPairs.derivePublicKey(
							elGamalMultiRecipientPrivateKey, generatorFromDifferentGroup));

			assertEquals("The private key and the generator must belong to groups of the same order.", illegalArgumentException.getMessage());
		}

		@Test
		@DisplayName("with a generator returns the expected public key.")
		void keyPairHasExpectedPublicKeyTest() {

			final GqElement generator = gqGroup.getGenerator();

			final ElGamalMultiRecipientPublicKey elGamalMultiRecipientPublicKey =
					new ElGamalMultiRecipientPublicKey(
							elGamalMultiRecipientPrivateKey.stream().map(generator::exponentiate).collect(Collectors.toList()));

			assertEquals(elGamalMultiRecipientPublicKey, ElGamalMultiRecipientKeyPairs.derivePublicKey(elGamalMultiRecipientPrivateKey, generator));
		}

	}
}
