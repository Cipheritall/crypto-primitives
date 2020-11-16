/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.math;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.math.BigInteger;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import ch.post.it.evoting.cryptoprimitives.test.tools.data.GqGroupLoader;

class GqElementValidationTest {

	private static GqGroup group;

	private static BigInteger p;

	private static BigInteger elementValue;

	@BeforeAll
	public static void setUp() throws IOException {

		group = new GqGroupLoader("/subgroup.json").getGroup();

		p = group.getP();

		elementValue = BigInteger.ONE;
	}

	public static Stream<Arguments> createGqElementFromGroupWithNulls() {
		return Stream.of(Arguments.of(null, group), Arguments.of(elementValue, null));
	}

	public static Stream<Arguments> createGqElementFromGroupWithInvalidValues() {
		return Stream.of(Arguments.of(BigInteger.ZERO, group), Arguments.of(p, group));
	}

	@ParameterizedTest
	@MethodSource("createGqElementFromGroupWithNulls")
	void testGqElementCreationWithNullThrows(BigInteger value, GqGroup group) {
		assertThrows(NullPointerException.class, () -> GqElement.create(value, group));
	}

	@ParameterizedTest
	@MethodSource("createGqElementFromGroupWithInvalidValues")
	void testGqElementCreationWithInvalidValuesThrows(BigInteger value, GqGroup group) {
		assertThrows(IllegalArgumentException.class, () -> GqElement.create(value, group));
	}
}
