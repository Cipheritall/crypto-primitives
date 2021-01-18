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

import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;

class ElGamalMultiRecipientPrivateKeyTest {

	private static ZqElement validExponent;
	private static ZqGroup validExponentGroup;
	private static ZqGroupGenerator generator;

	@BeforeAll
	static void setUp() {
		validExponentGroup = new ZqGroup(BigInteger.TEN);
		generator = new ZqGroupGenerator(validExponentGroup);
		validExponent = generator.genZqElementMember();
	}

	@Test
	void givenAnExponentOfZeroThenThrows() {
		ZqElement zeroExponent = ZqElement.create(BigInteger.ZERO, validExponentGroup);
		List<ZqElement> exponents = Arrays.asList(validExponent, zeroExponent);
		assertThrows(IllegalArgumentException.class, () -> new ElGamalMultiRecipientPrivateKey(exponents));
	}

	@Test
	void givenAnExponentOfOneThenThrows() {
		ZqElement oneExponent = ZqElement.create(BigInteger.ONE, validExponentGroup);
		List<ZqElement> exponents = Arrays.asList(validExponent, oneExponent);
		assertThrows(IllegalArgumentException.class, () -> new ElGamalMultiRecipientPrivateKey(exponents));
	}

	// Provides parameters for the withInvalidParameters test.
	static Stream<Arguments> createInvalidArgumentsProvider() {
		List<ZqElement> messageElementsFirstNull = new LinkedList<>();
		messageElementsFirstNull.add(null);
		messageElementsFirstNull.add(generator.genZqElementMember());

		List<ZqElement> messageElementsSecondNull = new LinkedList<>();
		messageElementsSecondNull.add(generator.genZqElementMember());
		messageElementsSecondNull.add(null);

		List<ZqElement> messageElementsDifferentGroups = new LinkedList<>();
		messageElementsDifferentGroups.add(generator.genZqElementMember());
		ZqGroupGenerator otherGenerator = new ZqGroupGenerator(generator.otherGroup());
		messageElementsDifferentGroups.add(otherGenerator.genZqElementMember());

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
}
