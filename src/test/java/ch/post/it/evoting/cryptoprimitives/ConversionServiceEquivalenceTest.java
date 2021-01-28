/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

class ConversionServiceEquivalenceTest {

	private static SecureRandom secureRandom;

	@BeforeAll
	static void setUp(){
		secureRandom = new SecureRandom();
	}

	@RepeatedTest(100)
	void randomBigIntegerConversionIsEquivalentWithTwoMethods() {
		int BIT_LENGTH = 2048;
		BigInteger random = new BigInteger(BIT_LENGTH, secureRandom);
		byte[] expected = ConversionService.integerToByteArraySpec(random);
		byte[] result = ConversionService.integerToByteArray(random);
		assertArrayEquals(expected, result);
	}

	@Test
	void testThrowsForNullValue() {
		assertThrows(NullPointerException.class, () -> ConversionService.integerToByteArray((BigInteger) null));
	}

	@Test
	void throwsForNegativeValue() {
		BigInteger value = BigInteger.valueOf(-1);
		assertThrows(IllegalArgumentException.class, () -> ConversionService.integerToByteArray(value));
	}

	@Test
	void sameByteArrayConversionForZero() {
		BigInteger x = BigInteger.ZERO;
		byte[] expected = ConversionService.integerToByteArraySpec(x);
		byte[] result = ConversionService.integerToByteArray(x);
		assertArrayEquals(expected, result);
	}

}
