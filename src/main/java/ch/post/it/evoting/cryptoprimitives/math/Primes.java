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

package ch.post.it.evoting.cryptoprimitives.math;

import java.math.BigInteger;

import ch.post.it.evoting.cryptoprimitives.internal.math.PrimesInternal;

public interface Primes {

	/**
	 * Checks if the given number is a prime number. This is efficient for small primes only.
	 *
	 * @param number n, the number to be tested. Must be non-null and strictly positive.
	 * @return true if n is prime, false otherwise.
	 * @throws NullPointerException     if n is null.
	 * @throws IllegalArgumentException if n is not strictly positive.
	 * @throws ArithmeticException      if n does not fit in an int (max is {@value Integer#MAX_VALUE}).
	 */
	static boolean isSmallPrime(final BigInteger number) {
		return PrimesInternal.isSmallPrime(number);
	}
}
