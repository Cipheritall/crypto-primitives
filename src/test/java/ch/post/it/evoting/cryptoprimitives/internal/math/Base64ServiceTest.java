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

class Base64ServiceTest {

	private static RandomService randomService;
	private static Base64Service base64Service;

	@BeforeAll
	static void setupAll() {
		randomService = new RandomService();
		base64Service = new Base64Service();
	}

	private static Stream<Arguments> getInputsAndOutputs() {
		return Stream.of(
				Arguments.of(new byte[] {}, ""),
				Arguments.of(new byte[] { 65 }, "QQ=="),
				Arguments.of(new byte[] { 96 }, "YA=="),
				Arguments.of(new byte[] { 0 }, "AA=="),
				Arguments.of(new byte[] { 127 }, "fw=="),
				Arguments.of(new byte[] { -128 }, "gA=="),
				Arguments.of(new byte[] { -1 }, "/w=="),
				Arguments.of(new byte[] { 65, 0 }, "QQA="),
				Arguments.of(new byte[] { 1, 1, 1 }, "AQEB"),
				Arguments.of(new byte[] { 127, 0, -2, 3 }, "fwD+Aw==")

		);
	}

	@ParameterizedTest
	@MethodSource("getInputsAndOutputs")
	@DisplayName("base64Encode with valid input gives expected output")
	void base64EncodeWithValidInputGivesExpectedResult(final byte[] input, final String expectedOutput) {
		final String result = base64Service.base64Encode(input);

		assertEquals(expectedOutput, result);
	}

	@ParameterizedTest
	@MethodSource("getInputsAndOutputs")
	@DisplayName("base64Decode with valid inputs gives expected output")
	void base64DecodeWithValidInputGivesExpectedResult(final byte[] expectedOutput, final String input) {
		final byte[] result = base64Service.base64Decode(input);

		assertArrayEquals(expectedOutput, result);
	}

	static Stream<String> getInvalidStrings() {
		return Stream.of("A=", "?sss", "Inv=====", "x-y.");
	}

	@ParameterizedTest
	@MethodSource("getInvalidStrings")
	@DisplayName("base64Decode with invalid strings throws an IllegalArgumentException")
	void base64DecodeWithInvalidStringsThrows(final String invalidString) {
		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> base64Service.base64Decode(invalidString));
		final String expectedErrorMessage = "The given string is not a valid Base64 string.";
		assertEquals(expectedErrorMessage, exception.getMessage());
	}

	@RepeatedTest(10)
	@DisplayName("base64Encode then base64Decode returns initial value")
	void base64EncodeThenBase64DecodeReturnsInitialValue() {
		final byte[] randomBytes = randomService.randomBytes(16);

		final String string = base64Service.base64Encode(randomBytes);
		final byte[] result = base64Service.base64Decode(string);
		assertArrayEquals(randomBytes, result);
	}
}