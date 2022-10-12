/*
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
 */

package ch.post.it.evoting.cryptoprimitives.internal.utils;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import com.google.common.base.Throwables;

import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.JsonData;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.TestParameters;

class ByteArraysTest {
	@Test
	void testCutToBitLengthWithNullThrows() {
		assertThrows(NullPointerException.class, () -> ByteArrays.cutToBitLength(null, 1));
	}

	@Test
	void testCutToBitLengtRequestedLengthZeroThrows() {
		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> ByteArrays.cutToBitLength(new byte[] { 0b10011 }, 0));
		assertEquals("The requested length must be strictly positive", Throwables.getRootCause(exception).getMessage());
	}

	@Test
	void testCutToBitLengthRequestedLengthGreaterThanByteArrayBitLengthThrows() {
		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> ByteArrays.cutToBitLength(new byte[] { 0b1001101 }, 9));
		assertEquals("The requested length must not be greater than the bit length of the byte array", Throwables.getRootCause(exception).getMessage());
	}

	static Stream<Arguments> jsonFileCutToBitLengthArgumentProvider() {

		final List<TestParameters> parametersList = TestParameters.fromResource("/cut-to-bit-length.json");

		return parametersList.stream().parallel().map(testParameters -> {

			final String description = testParameters.getDescription();

			final JsonData input = testParameters.getInput();
			final Integer bitLength = input.get("bit_length", Integer.class);
			final byte[] value = input.get("value", byte[].class);

			JsonData output = testParameters.getOutput();
			final byte[] result = output.get("result", byte[].class);

			return Arguments.of(value, bitLength, result, description);
		});
	}

	@ParameterizedTest
	@MethodSource("jsonFileCutToBitLengthArgumentProvider")
	@DisplayName("cutToBitLength of specific input returns expected output")
	void testCutToBitLengthWithRealValues(final byte[] byteArray, final int requestedLength, final byte[] expectedResult, final String description) {
		final byte[] actualResult = ByteArrays.cutToBitLength(byteArray, requestedLength);
		assertArrayEquals(expectedResult, actualResult, String.format("assertion failed for: %s", description));
	}

	@Test
	@DisplayName("byteLength with null argument throws NullPointerException")
	void testByteLengthWithNullThrows() {
		assertThrows(NullPointerException.class, () -> ByteArrays.byteLength(null));
	}

	static Stream<Arguments> byteLengthArgumentProvider() {
		return Stream.of(
				Arguments.of(BigInteger.ONE, 1),
				Arguments.of(BigInteger.valueOf(255), 1),
				Arguments.of(BigInteger.valueOf(256), 2),
				Arguments.of(BigInteger.valueOf(Integer.MAX_VALUE), 4)
		);
	}

	@ParameterizedTest
	@MethodSource("byteLengthArgumentProvider")
	@DisplayName("byteLength with valid input returns expected output")
	void testByteLengthWithValidUInputReturnsExpectedOutput(final BigInteger input, final int expectedOutput) {
		final int result = ByteArrays.byteLength(input);

		assertEquals(expectedOutput, result);
	}
}
