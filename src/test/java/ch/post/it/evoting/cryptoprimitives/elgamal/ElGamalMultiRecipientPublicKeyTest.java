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
}
