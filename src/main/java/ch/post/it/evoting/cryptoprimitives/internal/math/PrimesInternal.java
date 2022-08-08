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

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;

public class PrimesInternal {
	private PrimesInternal() {
		//Intentionally left blank
	}

	/**
	 * See {@link ch.post.it.evoting.cryptoprimitives.math.Primes#isSmallPrime}
	 */
	public static boolean isSmallPrime(final int number) {
		checkArgument(number > 0, "The number n must be strictly positive");
		final int n = number;

		if (n == 1) {
			return false;
		} else if (n == 2) {
			return true;
		} else {
			for (int i = 2; i <= Math.ceil(Math.sqrt(n)); i++) {
				if (n % i == 0) {
					return false;
				}
			}
		}

		return true;
	}
}
