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

import org.junit.jupiter.api.Test;

class PrimeTest {

	@Test
	void testIsSmallPrimeTrue() {
		assertTrue(PrimesInternal.isSmallPrime(2));
		assertTrue(PrimesInternal.isSmallPrime(3));
		assertTrue(PrimesInternal.isSmallPrime(5));
		assertTrue(PrimesInternal.isSmallPrime(7));
		assertTrue(PrimesInternal.isSmallPrime(11));
		assertTrue(PrimesInternal.isSmallPrime(47));
	}

	@Test
	void testIsSmallPrimeFalse() {
		assertFalse(PrimesInternal.isSmallPrime(1));
		assertFalse(PrimesInternal.isSmallPrime(4));
		assertFalse(PrimesInternal.isSmallPrime(9));
		assertFalse(PrimesInternal.isSmallPrime(35));
		assertFalse(PrimesInternal.isSmallPrime(77));
		assertFalse(PrimesInternal.isSmallPrime(143));
	}

	@Test
	void testIsSmallPrimeTooSmallNThrows() {
		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> PrimesInternal.isSmallPrime(0));
		assertEquals("The number n must be strictly positive", exception.getMessage());
	}
}
