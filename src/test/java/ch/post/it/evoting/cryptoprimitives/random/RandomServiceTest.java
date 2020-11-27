/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.random;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import java.math.BigInteger;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class RandomServiceTest {

	// RFC 4648 Table 1 and Table 3.
	private static final Pattern base64Alphabet = Pattern.compile("^[A-Za-z0-9+/=]+$");
	private static final Pattern base32Alphabet = Pattern.compile("^[A-Z2-7=]+$");

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

	@Test
	void genRandomBase32StringTest() {
		final String randomString1 = randomService.genRandomBase32String(6);
		final String randomString2 = randomService.genRandomBase32String(8);
		final String randomString3 = randomService.genRandomBase32String(1);

		assertAll(
				() -> assertEquals(6, randomString1.length()),
				() -> assertEquals(8, randomString2.length()),
				() -> assertEquals(1, randomString3.length())
		);

		// Check that the Strings chars are in the Base32 alphabet.
		assertAll(
				() -> assertTrue(base32Alphabet.matcher(randomString1).matches()),
				() -> assertTrue(base32Alphabet.matcher(randomString2).matches()),
				() -> assertTrue(base32Alphabet.matcher(randomString3).matches())
		);
	}

	@Test
	void genRandomBase32StringInvalidLengthShouldThrow() {
		assertThrows(IllegalArgumentException.class, () -> randomService.genRandomBase32String(0));
		assertThrows(IllegalArgumentException.class, () -> randomService.genRandomBase32String(1200));
	}

	@Test
	void genRandomBase64StringTest() {
		final String randomString1 = randomService.genRandomBase64String(6);
		final String randomString2 = randomService.genRandomBase64String(8);
		final String randomString3 = randomService.genRandomBase64String(1);

		assertAll(
				() -> assertEquals(6, randomString1.length()),
				() -> assertEquals(8, randomString2.length()),
				() -> assertEquals(1, randomString3.length())
		);

		// Check that the Strings chars are in the Base64 alphabet.
		assertAll(
				() -> assertTrue(base64Alphabet.matcher(randomString1).matches()),
				() -> assertTrue(base64Alphabet.matcher(randomString2).matches()),
				() -> assertTrue(base64Alphabet.matcher(randomString3).matches())
		);
	}

	@Test
	void genRandomBase64StringInvalidLengthShouldThrow() {
		assertThrows(IllegalArgumentException.class, () -> randomService.genRandomBase64String(-1));
		assertThrows(IllegalArgumentException.class, () -> randomService.genRandomBase64String(4000));
	}

}