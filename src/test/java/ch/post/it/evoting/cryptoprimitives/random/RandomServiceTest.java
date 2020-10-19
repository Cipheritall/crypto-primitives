/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.random;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.Mockito.doReturn;

import java.math.BigInteger;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;

import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

class RandomServiceTest {

	// RFC 4648 Table 1 and Table 3.
	private static final Pattern base64Alphabet = Pattern.compile("^[A-Za-z0-9+/=]+$");
	private static final Pattern base32Alphabet = Pattern.compile("^[A-Z2-7=]+$");

	private final RandomService randomService = new RandomService();
	private static ZqGroup smallGroup;
	private static ZqGroup largeGroup;

	@BeforeAll
	static void setUp() {
		BigInteger smallQ = BigInteger.valueOf(11);
		smallGroup = new ZqGroup(smallQ);

		BigInteger largeQ = new BigInteger(
				"129393962833354210499210688582114332331264955144078865695142258397576823398124617906793313278446446028832209901197744118689034771985"
						+ "09705601122060967876228374690884782515835193957431967788948058212827424653299092753997868946254919808472248036853722669403"
						+ "05071273369448896874451022839183805131028098532234200793438301404002468642493605752610410721973630167774154782002075773042"
						+ "57379855591360625666120039748442218402148340456567370594375408103734599537838411991045221718260736643114334173004199390571"
						+ "42509409231555113555807016335721042732921970354542359833932880562757400121671030866342014401323096601105149589569705303",
				10);
		largeGroup = new ZqGroup(largeQ);
	}

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
		BigInteger minusOne = BigInteger.ONE.negate();
		assertThrows(IllegalArgumentException.class, () -> randomService.genRandomInteger(minusOne));
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
	void givenNullGroupWhenAttemptToCreateZqElementThenException() {
		assertThrows(NullPointerException.class, () -> randomService.genRandomExponent(null));
	}

	@RepeatedTest(10)
	void testWhenRandomZqElementCreatedThenValueIsInRange() {
		ZqElement randomExponent = randomService.genRandomExponent(smallGroup);

		assertTrue(randomExponent.getValue().compareTo(BigInteger.valueOf(2)) >= 0, "The random exponent should be equal or greater than 2");
		assertTrue(randomExponent.getValue().compareTo(smallGroup.getQ()) < 0, "The random exponent should be less than q");
	}

	@Test
	void testGenRandomExponentUsesRandomness() {
		String errorMessage = "The random exponents should be different";

		RandomService spyRandomService = Mockito.spy(new RandomService());

		doReturn(BigInteger.ZERO, BigInteger.ONE, BigInteger.valueOf(2))
				.when(spyRandomService).genRandomIntegerWithinBounds(ArgumentMatchers.any(), ArgumentMatchers.any());

		ZqElement exponent1 = randomService.genRandomExponent(largeGroup);
		ZqElement exponent2 = randomService.genRandomExponent(largeGroup);
		ZqElement exponent3 = randomService.genRandomExponent(largeGroup);

		assertNotEquals(exponent1.getValue(), exponent2.getValue(), errorMessage);
		assertNotEquals(exponent1.getValue(), exponent3.getValue(), errorMessage);
		assertNotEquals(exponent2.getValue(), exponent3.getValue(), errorMessage);
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