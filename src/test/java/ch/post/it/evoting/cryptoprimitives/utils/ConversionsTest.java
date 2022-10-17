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
import static ch.post.it.evoting.cryptoprimitives.internal.utils.ConversionsInternal.byteArrayToString;
import static ch.post.it.evoting.cryptoprimitives.internal.utils.ConversionsInternal.integerToByteArray;
import static ch.post.it.evoting.cryptoprimitives.internal.utils.ConversionsInternal.integerToString;
import static ch.post.it.evoting.cryptoprimitives.internal.utils.ConversionsInternal.stringToByteArray;
import static ch.post.it.evoting.cryptoprimitives.internal.utils.ConversionsInternal.stringToInteger;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import ch.post.it.evoting.cryptoprimitives.internal.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.internal.utils.ByteArrays;

class ConversionsTest {

	private static Random random;

	@BeforeAll
	static void setUp() {
		random = new SecureRandom();
	}

	@Nested
	@DisplayName("Test BigInteger to byte array conversion")
	class IntegerToByteArrayTest {
		@Test
		void testConversionOfNullBigIntegerToByteArrayThrows() {
			assertThrows(NullPointerException.class, () -> integerToByteArray(null));
		}

		@Test
		void testConversionOfZeroBigIntegerIsOneZeroByte() {
			BigInteger zero = BigInteger.ZERO;
			byte[] expected = new byte[] { 0 };
			byte[] converted = integerToByteArray(zero);
			assertArrayEquals(expected, converted);
		}

		@Test
		void testConversionOf256BigIntegerIsTwoBytes() {
			BigInteger value = BigInteger.valueOf(256);
			byte[] expected = new byte[] { 1, 0 };
			byte[] converted = integerToByteArray(value);
			assertArrayEquals(expected, converted);
		}

		@Test
		void testConversionOfIntegerMaxValuePlusOneIsCorrect() {
			BigInteger value = BigInteger.valueOf(Integer.MAX_VALUE).add(BigInteger.ONE);
			byte[] expected = new byte[] { (byte) 0b10000000, 0, 0, 0 };
			byte[] converted = integerToByteArray(value);
			assertArrayEquals(expected, converted);
		}

		@Test
		void testOfNegativeBigIntegerThrows() {
			BigInteger value = BigInteger.valueOf(-1);
			assertThrows(IllegalArgumentException.class, () -> integerToByteArray(value));
		}

		@RepeatedTest(10)
		void testIntegerToByteArrayIsEquivalentToSpecification() {
			final BigInteger bigInteger = BigInteger.valueOf(random.nextInt(0, Integer.MAX_VALUE));

			assertArrayEquals(integerToByteArraySpec(bigInteger), integerToByteArray(bigInteger));
		}

		/*
		 * This implementation is faithful to the specification.
		 */
		private byte[] integerToByteArraySpec(final BigInteger integer) {
			final BigInteger TWOHUNDRED_FIFTY_SIX = BigInteger.valueOf(256);
			BigInteger x = integer;
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

	@Nested
	@DisplayName("Test byte array to BigInteger conversion")
	class ByteArrayToIntegerTest {
		@Test
		void testConversionOfNullToBigIntegerThrows() {
			assertThrows(NullPointerException.class, () -> byteArrayToInteger(null));
		}

		@Test
		void testConversionOfEmptyByteArrayToBigIntegerThrows() {
			final IllegalArgumentException illegalArgumentException =
					assertThrows(IllegalArgumentException.class, () -> byteArrayToInteger(new byte[] {}));

			assertEquals("The byte array to convert must be non-empty.", illegalArgumentException.getMessage());
		}

		@Test
		void testConversionOfByteArrayWithLeading1ToBigIntegerIsPositive() {
			byte[] bytes = new byte[] { (byte) 0x80 };
			BigInteger converted = byteArrayToInteger(bytes);
			assertTrue(converted.compareTo(BigInteger.ZERO) > 0);
		}

		@Test
		void testConversionOf256ByteArrayRepresentationIs256() {
			byte[] bytes = new byte[] { 1, 0 };
			BigInteger converted = byteArrayToInteger(bytes);
			assertEquals(0, converted.compareTo(BigInteger.valueOf(256)));
		}

		//Cyclic test BigInteger to byte array and back
		@RepeatedTest(10)
		void testRandomBigIntegerToByteArrayAndBackIsOriginalValue() {
			int size = random.nextInt(32);
			BigInteger value = new BigInteger(size, random);
			BigInteger cycledValue = byteArrayToInteger(integerToByteArray(value));
			assertEquals(value, cycledValue);
		}

		@RepeatedTest(10)
		void testByteArrayToIntegerIsEquivalentToSpec() {
			byte[] byteArray = new byte[32];
			random.nextBytes(byteArray);

			assertEquals(byteArrayToIntegerSpec(byteArray), byteArrayToInteger(byteArray));
		}

		/*
		 * This implementation is faithful to the specification.
		 */
		private BigInteger byteArrayToIntegerSpec(final byte[] byteArray) {
			final byte[] B = byteArray.clone();
			final int n = byteArray.length;

			BigInteger x = BigInteger.ZERO;
			for (int i = 0; i < n; i++) {
				x = BigInteger.valueOf(256).multiply(x).add(BigInteger.valueOf(Byte.toUnsignedInt(B[i])));
			}
			return x;
		}
	}

	@Nested
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	@DisplayName("Test String to BigInteger conversion")
	class StringToIntegerTest {

		Stream<Arguments> stringToIntegerWithValidInputIsOkProvider() {
			return Stream.of(
					Arguments.of("0", BigInteger.ZERO),
					Arguments.of("1", BigInteger.ONE),
					Arguments.of("1001", BigInteger.valueOf(1001L)),
					Arguments.of("0021", BigInteger.valueOf(21L))
			);
		}

		@ParameterizedTest(name = "s = \"{0}\", expected = {1}")
		@MethodSource("stringToIntegerWithValidInputIsOkProvider")
		void stringToIntegerWithValidInputIsOk(final String s, final BigInteger expected) {
			final BigInteger converted = stringToInteger(s);
			assertEquals(expected, converted);
		}

		Stream<Arguments> stringToIntegerWithNonValidInputThrowsIllegalArgumentExceptionProvider() {
			return Stream.of(
					Arguments.of("", "The string to convert cannot be empty."),
					Arguments.of("A", "The string to convert \"A\" is not a valid decimal representation of a BigInteger."),
					Arguments.of("1A", "The string to convert \"1A\" is not a valid decimal representation of a BigInteger."),
					Arguments.of("A1", "The string to convert \"A1\" is not a valid decimal representation of a BigInteger."),
					Arguments.of("+1", "The string to convert \"+1\" is not a valid decimal representation of a BigInteger."),
					Arguments.of("1+", "The string to convert \"1+\" is not a valid decimal representation of a BigInteger."),
					Arguments.of("-1", "The string to convert \"-1\" is not a valid decimal representation of a BigInteger."),
					Arguments.of("1-", "The string to convert \"1-\" is not a valid decimal representation of a BigInteger.")
			);
		}

		@ParameterizedTest(name = "s = \"{0}\", expectedExceptionMessage = \"{1}\"")
		@MethodSource("stringToIntegerWithNonValidInputThrowsIllegalArgumentExceptionProvider")
		void stringToIntegerWithNonValidInputThrowsIllegalArgumentException(final String s, final String expectedExceptionMessage) {
			final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class, () -> stringToInteger(s));

			assertEquals(expectedExceptionMessage, illegalArgumentException.getMessage());
		}

		@Test
		void stringToIntegerWithNullInputThrowsNullPointerException() {
			assertThrows(NullPointerException.class, () -> stringToInteger(null));
		}
	}

	@Nested
	@DisplayName("Test BigInteger/Integer to String conversion")
	class IntegerToStringTest {
		@Test
		void testIntegerToStringWithNullInputThrowsNullPointerException() {
			assertThrows(NullPointerException.class, () -> integerToString((BigInteger) null));

			assertThrows(NullPointerException.class, () -> integerToString((Integer) null));
		}

		@Test
		void testIntegerToStringWithNegativeInputThrowsIllegalArgumentException() {
			BigInteger x = BigInteger.valueOf(-1L);
			assertThrows(IllegalArgumentException.class, () -> integerToString(x));

			Integer y = -1;
			assertThrows(IllegalArgumentException.class, () -> integerToString(y));
		}
	}

	@Nested
	@DisplayName("Cyclic test BigInteger/Integer to String conversion and back")
	class CyclicIntegerToStringTest {
		@Test
		void testZeroBigIntegerToStringAndBackIsOriginalValue() {
			BigInteger value = BigInteger.ZERO;
			BigInteger cycledValue = stringToInteger(integerToString(value));
			assertEquals(value, cycledValue);
		}

		//Cyclic test BigInteger to String and back
		@RepeatedTest(10)
		void testRandomBigIntegerToStringAndBackIsOriginalValue() {
			int size = random.nextInt(32);
			BigInteger value = new BigInteger(size, random);
			BigInteger cycledValue = stringToInteger(integerToString(value));
			assertEquals(value, cycledValue);
		}

		@Test
		void testZeroIntegerToStringAndBackIsOriginalValue() {
			Integer value = 0;
			Integer cycledValue = stringToInteger(integerToString(value)).intValue();
			assertEquals(value, cycledValue);
		}

		@RepeatedTest(10)
		void testRandomIntegerToStringAndBackIsOriginalValue() {
			Integer value = random.nextInt(32);
			Integer cycledValue = stringToInteger(integerToString(value)).intValue();
			assertEquals(value, cycledValue);
		}
	}

	@Nested
	@DisplayName("Test String to byte array conversion")
	class StringToByteArrayTest {
		@Test
		void testConversionOfNullStringToByteArrayThrows() {
			assertThrows(NullPointerException.class, () -> stringToByteArray(null));
		}
	}

	@Nested
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	@DisplayName("Test byte array to String conversion")
	class ByteArrayToStringTest {
		@Test
		void testConversionOfNullByteArrayToStringThrows() {
			assertThrows(NullPointerException.class, () -> byteArrayToString(null));
		}

		@Test
		void testConversionOfZeroLengthByteArrayToStringThrows() {
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> byteArrayToString(new byte[] {}));
			assertEquals("The length of the byte array must be strictly positive.", exception.getMessage());
		}

		Stream<Arguments> invalidUTF8ByteArrays() {
			return Stream.of(
					Arguments.of(new byte[] { -37, -10 }),
					Arguments.of(new byte[] { -50, -29, 48 }),
					Arguments.of(new byte[] { 107, -93, 75, 41 })
			);
		}

		@ParameterizedTest(name = "byteArray = \"{0}\"")
		@MethodSource("invalidUTF8ByteArrays")
		void testConversionOfInvalidUTF8ByteArrayToStringThrows(byte[] byteArray) {
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> byteArrayToString(byteArray));
			assertEquals("The byte array does not correspond to a valid sequence of UTF-8 encoding.", exception.getMessage());
		}

	}

	@Nested
	@DisplayName("Cyclic test String to byte array conversion and back")
	class CyclicStringToByteArrayTest {
		RandomService randomService = new RandomService();

		@RepeatedTest(10)
		void testRandomStringToByteArrayAndBackIsOriginalValue() {
			String value = randomService.genRandomBase64String(random.nextInt(10) + 1);
			byte[] bytes = stringToByteArray(value);
			final String cycledValue = byteArrayToString(bytes);
			assertEquals(value, cycledValue);
		}
	}

}
