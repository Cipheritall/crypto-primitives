/*
 *
 * Copyright 2022 Post CH Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package ch.post.it.evoting.cryptoprimitives.utils;

import static ch.post.it.evoting.cryptoprimitives.internal.utils.ConversionsInternal.byteArrayToInteger;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.internal.utils.ByteArrays;
import ch.post.it.evoting.cryptoprimitives.internal.utils.ConversionsInternal;

class ConversionsEquivalenceTest {

	private static SecureRandom secureRandom;

	@BeforeAll
	static void setUp() {
		secureRandom = new SecureRandom();
	}

	@RepeatedTest(100)
	void randomBigIntegerConversionIsEquivalentWithTwoMethods() {
		final int BIT_LENGTH = 2048;
		final BigInteger random = new BigInteger(BIT_LENGTH, secureRandom);
		final byte[] expected = integerToByteArraySpec(random);
		final byte[] result = ConversionsInternal.integerToByteArray(random);
		assertArrayEquals(expected, result);
	}

	@RepeatedTest(1000)
	void testByteArrayToIntegerIsEquivalentToSpec() {
		byte[] byteArray = new byte[32];
		secureRandom.nextBytes(byteArray);

		assertEquals(byteArrayToIntegerSpec(byteArray), byteArrayToInteger(byteArray));
	}

	@Test
	void sameByteArrayConversionForZero() {
		final BigInteger x = BigInteger.ZERO;
		final byte[] expected = integerToByteArraySpec(x);
		final byte[] result = ConversionsInternal.integerToByteArray(x);
		assertArrayEquals(expected, result);
	}

	/**
	 * Implements the specification ByteArrayToInteger algorithm. It is used in tests to show that it is equivalent to the more performant method used
	 * which is implemented in {@link ConversionsInternal#byteArrayToInteger}.
	 *
	 * @param byteArray B, the byte array to convert.
	 * @return the BigInteger representation of this byte array.
	 **/
	private BigInteger byteArrayToIntegerSpec(final byte[] byteArray) {
		final byte[] B = byteArray.clone();
		final int n = byteArray.length;

		BigInteger x = BigInteger.ZERO;
		for (int i = 0; i < n; i++) {
			x = BigInteger.valueOf(256).multiply(x).add(BigInteger.valueOf(Byte.toUnsignedInt(B[i])));
		}
		return x;
	}

	/**
	 * Implements the specification IntegerToByteArray algorithm. It is used in tests to show that it is equivalent to the more performant method used
	 * which is implemented in {@link ConversionsInternal#integerToByteArray}.
	 *
	 * @param integer x, the positive BigInteger to convert.
	 * @return the byte array representation of this BigInteger.
	 **/
	static byte[] integerToByteArraySpec(final BigInteger integer) {
		final BigInteger TWOHUNDRED_FIFTY_SIX = BigInteger.valueOf(256);
		BigInteger x = integer;

		// Operation
		int n = ByteArrays.byteLength(x);
		n = Math.max(n, 1);
		final byte[] B = new byte[n];
		for (int i = 0; i < n; i++) {
			B[n-i-1] = x.mod(TWOHUNDRED_FIFTY_SIX).byteValue();
			x = x.divide(TWOHUNDRED_FIFTY_SIX);
		}
		return B;
	}
}
