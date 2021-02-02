/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.elgamal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GqGroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;

class ElGamalMultiRecipientPublicKeyTest {

	private static GqGroupGenerator generator;
	private static GqGroup gqGroup;

	@BeforeAll
	static void setUpAll() {
		gqGroup = GqGroupTestData.getGroup();
		generator = new GqGroupGenerator(gqGroup);
	}

	@Test
	void givenAnKeyElementOfOneThenThrows() {
		GqElement oneKeyElement = GqElement.create(BigInteger.ONE, gqGroup);
		List<GqElement> exponents = Arrays.asList(generator.genMember(), oneKeyElement);
		assertThrows(IllegalArgumentException.class, () -> new ElGamalMultiRecipientPublicKey(exponents));
	}

	@Test
	void givenAnKeyElementEqualToGeneratorThenThrows() {
		GqElement generatorKeyElement = GqElement.create(gqGroup.getGenerator().getValue(), gqGroup);
		List<GqElement> exponents = Arrays.asList(generator.genMember(), generatorKeyElement);
		assertThrows(IllegalArgumentException.class, () -> new ElGamalMultiRecipientPublicKey(exponents));
	}

	// Provides parameters for the withInvalidParameters test.
	static Stream<Arguments> createInvalidArgumentsProvider() {
		List<GqElement> keyElementsFirstNull = new LinkedList<>();
		keyElementsFirstNull.add(null);
		keyElementsFirstNull.add(generator.genMember());

		List<GqElement> keyElementsSecondNull = new LinkedList<>();
		keyElementsSecondNull.add(generator.genMember());
		keyElementsSecondNull.add(null);

		List<GqElement> keyElementsDifferentGroups = new LinkedList<>();
		keyElementsDifferentGroups.add(generator.genMember());
		GqGroup other = GqGroupTestData.getDifferentGroup(gqGroup);
		GqGroupGenerator otherGenerator = new GqGroupGenerator(other);
		keyElementsDifferentGroups.add(otherGenerator.genMember());

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
