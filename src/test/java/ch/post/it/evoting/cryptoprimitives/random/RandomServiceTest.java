/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.random;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import java.math.BigInteger;
import java.util.stream.Stream;

import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class RandomServiceTest {

	private final RandomService randomService = new RandomService();

	static Stream<Arguments> createLowerAndUpperBounds() {
		return Stream.of(
				arguments(BigInteger.valueOf(1849), BigInteger.valueOf(1849)),
				arguments(BigInteger.valueOf(1849), BigInteger.valueOf(1848))
		);
	}

	@RepeatedTest(1000)
	void genRandomIntegerTest() {
		final BigInteger upperBound = BigInteger.valueOf(100);
		final BigInteger randomInteger = randomService.genRandomInteger(upperBound);

		assertTrue(randomInteger.compareTo(upperBound) < 0);
		assertTrue(randomInteger.compareTo(BigInteger.ZERO) >= 0);
	}

	@Test
	void genRandomIntegerWithInvalidUpperBounds() {
		assertThrows(NullPointerException.class, () -> randomService.genRandomInteger(null));
		assertThrows(IllegalArgumentException.class, () -> randomService.genRandomInteger(BigInteger.ZERO));
		assertThrows(IllegalArgumentException.class, () -> randomService.genRandomInteger(BigInteger.valueOf(-1L)));
	}

	@Test
	void testGenerateRandomIntegerWithinBounds() {
		BigInteger lowerBound = BigInteger.ONE;
		BigInteger upperBound = BigInteger.valueOf(1849);
		BigInteger randomInteger = randomService.genRandomIntegerWithinBounds(lowerBound, upperBound);

		assertTrue(randomInteger.compareTo(lowerBound) >= 0);
		assertTrue(randomInteger.compareTo(upperBound) < 0);
	}

	@ParameterizedTest
	@MethodSource("createLowerAndUpperBounds")
	void testGenerateRandomIntegerWithinBoundUpperEqualsLowerFails(BigInteger lowerBound, BigInteger upperBound) {
		assertThrows(IllegalArgumentException.class, () -> randomService.genRandomIntegerWithinBounds(lowerBound, upperBound));
	}

}