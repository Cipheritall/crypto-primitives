/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.math;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;

import org.junit.jupiter.api.Test;

class BigIntegerOperationsTest {

	private static final BigInteger MINUS_ONE = BigInteger.valueOf(-1L);
	private static final BigInteger TWO = BigInteger.valueOf(2L);
	private static final BigInteger THREE = BigInteger.valueOf(3L);
	private static final BigInteger FIVE = BigInteger.valueOf(5L);
	private static final BigInteger SIX = BigInteger.valueOf(6L);
	private static final BigInteger SEVEN = BigInteger.valueOf(7L);

	@Test
	void modMultiplyTest() {
		assertEquals(SIX, BigIntegerOperations.modMultiply(TWO, THREE, SEVEN));
		assertEquals(BigInteger.ONE, BigIntegerOperations.modMultiply(THREE, FIVE, SEVEN));
	}

	@Test
	void modMultiplyInvalidModulus() {
		assertThrows(ArithmeticException.class, () -> BigIntegerOperations.modMultiply(TWO, SIX, BigInteger.ZERO));
		assertThrows(ArithmeticException.class, () -> BigIntegerOperations.modMultiply(TWO, SIX, MINUS_ONE));
	}

	@Test
	void checkModPow() {
		assertEquals(BigInteger.ONE, BigIntegerOperations.modPow(TWO, THREE, SEVEN));
		assertEquals(FIVE, BigIntegerOperations.modPow(THREE, FIVE, SEVEN));
	}

	@Test
	void modPowInvalidModulus() {
		assertThrows(ArithmeticException.class, () -> BigIntegerOperations.modPow(TWO, SIX, BigInteger.ZERO));
		assertThrows(ArithmeticException.class, () -> BigIntegerOperations.modPow(TWO, SIX, MINUS_ONE));
	}
}
