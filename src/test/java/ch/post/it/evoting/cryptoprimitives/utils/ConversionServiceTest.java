/*
 *
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
 *
 */
package ch.post.it.evoting.cryptoprimitives.utils;

import static ch.post.it.evoting.cryptoprimitives.utils.ConversionService.byteArrayToInteger;
import static ch.post.it.evoting.cryptoprimitives.utils.ConversionService.integerToString;
import static ch.post.it.evoting.cryptoprimitives.utils.ConversionService.stringToInteger;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class ConversionServiceTest {

	private static Random random;

	@BeforeAll
	static void setUp() {
		random = new SecureRandom();
	}

	//Test BigInteger to ByteArray conversion
	@Test
	void testConversionOfNullBigIntegerToByteArrayThrows() {
		assertThrows(NullPointerException.class, () -> ConversionService.integerToByteArray((BigInteger) null));
	}

	@Test
	void testConversionOfZeroBigIntegerIsOneZeroByte() {
		BigInteger zero = BigInteger.ZERO;
		byte[] expected = new byte[] { 0 };
		byte[] converted = ConversionService.integerToByteArray(zero);
		assertArrayEquals(expected, converted);
	}

	@Test
	void testConversionOf256BigIntegerIsTwoBytes() {
		BigInteger value = BigInteger.valueOf(256);
		byte[] expected = new byte[] { 1, 0 };
		byte[] converted = ConversionService.integerToByteArray(value);
		assertArrayEquals(expected, converted);
	}

	@Test
	void testConversionOfIntegerMaxValuePlusOneIsCorrect() {
		BigInteger value = BigInteger.valueOf(Integer.MAX_VALUE).add(BigInteger.ONE);
		byte[] expected = new byte[] { (byte) 0b10000000, 0, 0, 0 };
		byte[] converted = ConversionService.integerToByteArray(value);
		assertArrayEquals(expected, converted);
	}

	@Test
	void testOfNegativeBigIntegerThrows() {
		BigInteger value = BigInteger.valueOf(-1);
		assertThrows(IllegalArgumentException.class, () -> ConversionService.integerToByteArray(value));
	}

	//Test byte array to BigInteger conversion
	@Test
	void testConversionOfNullToBigIntegerThrows() {
		assertThrows(NullPointerException.class, () -> byteArrayToInteger((byte[]) null));
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
		BigInteger cycledValue = byteArrayToInteger(ConversionService.integerToByteArray(value));
		assertEquals(value, cycledValue);
	}

	@ParameterizedTest(name = "s = \"{0}\", expected = {1}")
	@MethodSource("stringToIntegerWithValidInputIsOkProvider")
	void stringToIntegerWithValidInputIsOk(final String s, final BigInteger expected) {
		final BigInteger converted = ConversionService.stringToInteger(s);
		assertEquals(expected, converted);
	}

	static Stream<Arguments> stringToIntegerWithValidInputIsOkProvider() {
		return Stream.of(
				Arguments.of("0", BigInteger.ZERO),
				Arguments.of("1", BigInteger.ONE),
				Arguments.of("1001", BigInteger.valueOf(1001L)),
				Arguments.of("0021", BigInteger.valueOf(21L))
		);
	}

	@ParameterizedTest(name = "s = \"{0}\", expectedExceptionMessage = \"{1}\"")
	@MethodSource("stringToIntegerWithNonValidInputThrowsIllegalArgumentExceptionProvider")
	void stringToIntegerWithNonValidInputThrowsIllegalArgumentException(final String s, final String expectedExceptionMessage) {
		final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class, () -> stringToInteger(s));

		assertEquals(expectedExceptionMessage, illegalArgumentException.getMessage());
	}

	static Stream<Arguments> stringToIntegerWithNonValidInputThrowsIllegalArgumentExceptionProvider() {
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

	@Test
	void stringToIntegerWithNullInputThrowsNullPointerException() {
		assertThrows(NullPointerException.class, () -> stringToInteger(null));
	}

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

	@Test
	void testZeroBigIntegerToStringAndBackIsOriginalValue() {
		BigInteger value = BigInteger.ZERO;
		BigInteger cycledValue = stringToInteger(ConversionService.integerToString(value));
		assertEquals(value, cycledValue);
	}

	//Cyclic test BigInteger to String and back
	@RepeatedTest(10)
	void testRandomBigIntegerToStringAndBackIsOriginalValue() {
		int size = random.nextInt(32);
		BigInteger value = new BigInteger(size, random);
		BigInteger cycledValue = stringToInteger(ConversionService.integerToString(value));
		assertEquals(value, cycledValue);
	}

	@Test
	void testZeroIntegerToStringAndBackIsOriginalValue() {
		Integer value = 0;
		Integer cycledValue = stringToInteger(ConversionService.integerToString(value)).intValue();
		assertEquals(value, cycledValue);
	}

	//Cyclic test Integer to String and back
	@RepeatedTest(10)
	void testRandomIntegerToStringAndBackIsOriginalValue() {
		Integer value = random.nextInt(32);
		Integer cycledValue = stringToInteger(ConversionService.integerToString(value)).intValue();
		assertEquals(value, cycledValue);
	}
}
