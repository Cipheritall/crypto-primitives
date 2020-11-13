package ch.post.it.evoting.cryptoprimitives.random;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;

import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

class RandomServiceTest {

	private final RandomService randomService = new RandomService();

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

}