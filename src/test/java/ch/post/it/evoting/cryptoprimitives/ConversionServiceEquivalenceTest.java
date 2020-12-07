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
		byte[] expected = ConversionService.toByteArraySpec(random);
		byte[] result = ConversionService.toByteArray(random);
		assertArrayEquals(expected, result);
	}

	@Test
	void testThrowsForNullValue() {
		assertThrows(NullPointerException.class, () -> ConversionService.toByteArray((BigInteger) null));
	}

	@Test
	void throwsForNegativeValue() {
		BigInteger value = BigInteger.valueOf(-1);
		assertThrows(IllegalArgumentException.class, () -> ConversionService.toByteArray(value));
	}

	@Test
	void sameByteArrayConversionForZero() {
		BigInteger x = BigInteger.ZERO;
		byte[] expected = ConversionService.toByteArraySpec(x);
		byte[] result = ConversionService.toByteArray(x);
		assertArrayEquals(expected, result);
	}

}
