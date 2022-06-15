/*
 * Copyright 2022 Post CH Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package ch.post.it.evoting.cryptoprimitives.internal.math;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;

import org.junit.jupiter.api.Test;

class PrimeTest {
	private static final BigInteger ZERO = BigInteger.ZERO;
	private static final BigInteger ONE = BigInteger.ONE;
	private static final BigInteger TWO = BigInteger.valueOf(2L);
	private static final BigInteger THREE = BigInteger.valueOf(3L);
	private static final BigInteger FOUR = BigInteger.valueOf(4L);
	private static final BigInteger FIVE = BigInteger.valueOf(5L);
	private static final BigInteger SEVEN = BigInteger.valueOf(7L);
	private static final BigInteger NINE = BigInteger.valueOf(9L);

	@Test
	void testIsSmallPrimeTrue() {
		assertTrue(PrimesInternal.isSmallPrime(TWO));
		assertTrue(PrimesInternal.isSmallPrime(THREE));
		assertTrue(PrimesInternal.isSmallPrime(FIVE));
		assertTrue(PrimesInternal.isSmallPrime(SEVEN));
		assertTrue(PrimesInternal.isSmallPrime(BigInteger.valueOf(11L)));
		assertTrue(PrimesInternal.isSmallPrime(BigInteger.valueOf(47L)));
	}

	@Test
	void testIsSmallPrimeFalse() {
		assertFalse(PrimesInternal.isSmallPrime(ONE));
		assertFalse(PrimesInternal.isSmallPrime(FOUR));
		assertFalse(PrimesInternal.isSmallPrime(NINE));
		assertFalse(PrimesInternal.isSmallPrime(BigInteger.valueOf(35L)));
		assertFalse(PrimesInternal.isSmallPrime(BigInteger.valueOf(77L)));
		assertFalse(PrimesInternal.isSmallPrime(BigInteger.valueOf(143L)));
	}

	@Test
	void testIsSmallPrimeTooSmallNThrows() {
		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> PrimesInternal.isSmallPrime(ZERO));
		assertEquals("The number n must be strictly positive", exception.getMessage());
	}

	@Test
	void testIsSmallPrimeTooBigNThrows() {
		final BigInteger maxIntPlusOne = BigInteger.valueOf(Integer.MAX_VALUE).add(ONE);
		final ArithmeticException exception = assertThrows(ArithmeticException.class,
				() -> PrimesInternal.isSmallPrime(maxIntPlusOne));
		assertEquals("BigInteger out of int range", exception.getMessage());
	}
}
