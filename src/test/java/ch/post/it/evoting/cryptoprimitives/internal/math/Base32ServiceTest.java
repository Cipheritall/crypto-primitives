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
package ch.post.it.evoting.cryptoprimitives.internal.math;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class Base32ServiceTest {

	private static RandomService randomService;
	private static Base32Service base32Service;

	@BeforeAll
	static void setupAll() {
		randomService = new RandomService();
		base32Service = new Base32Service();
	}

	private static Stream<Arguments> getInputsAndOutputs() {
		return Stream.of(
				Arguments.of(new byte[] {}, ""),
				Arguments.of(new byte[] { 65 }, "IE======"),
				Arguments.of(new byte[] { 96 }, "MA======"),
				Arguments.of(new byte[] { 0 }, "AA======"),
				Arguments.of(new byte[] { 127 }, "P4======"),
				Arguments.of(new byte[] { -128 }, "QA======"),
				Arguments.of(new byte[] { -1 }, "74======"),
				Arguments.of(new byte[] { 65, 0 }, "IEAA===="),
				Arguments.of(new byte[] { 1, 1, 1 }, "AEAQC==="),
				Arguments.of(new byte[] { 127, 0, -2, 3 }, "P4AP4AY=")

		);
	}

	@ParameterizedTest
	@MethodSource("getInputsAndOutputs")
	@DisplayName("base32Encode with valid input gives expected output")
	void base32EncodeWithValidInputGivesExpectedResult(final byte[] input, final String expectedOutput) {
		final String result = base32Service.base32Encode(input);

		assertEquals(expectedOutput, result);
	}

	@ParameterizedTest
	@MethodSource("getInputsAndOutputs")
	@DisplayName("base32Decode with valid inputs gives expected output")
	void base32DecodeWithValidInputGivesExpectedResult(final byte[] expectedOutput, final String input) {
		final byte[] result = base32Service.base32Decode(input);

		assertArrayEquals(expectedOutput, result);
	}

	static Stream<String> getInvalidStrings() {
		return Stream.of("A=", "ABCDEFGh", "01======", "ABC=====");
	}

	@ParameterizedTest
	@MethodSource("getInvalidStrings")
	@DisplayName("base32Decode with invalid strings throws an IllegalArgumentException")
	void base32DecodeWithInvalidStringsThrows(final String invalidString) {
		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> base32Service.base32Decode(invalidString));
		final String expectedErrorMessage = "The given string is not a valid Base32 string.";
		assertEquals(expectedErrorMessage, exception.getMessage());
	}

	@RepeatedTest(10)
	@DisplayName("base32Encode then base32Decode returns initial value")
	void base32EncodeThenBase32DecodeReturnsInitialValue() {
		final byte[] randomBytes = randomService.randomBytes(16);

		final String string = base32Service.base32Encode(randomBytes);
		final byte[] result = base32Service.base32Decode(string);
		assertArrayEquals(randomBytes, result);
	}
}