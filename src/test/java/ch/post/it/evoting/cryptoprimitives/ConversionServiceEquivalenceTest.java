/*
 * Copyright 2021 Post CH Ltd
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
