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

import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class Base16ServiceTest {

	private static RandomService randomService;
	private static Base16Service base16Service;

	@BeforeAll
	static void setupAll() {
		randomService = new RandomService();
		base16Service = new Base16Service();
	}

	private static Stream<Arguments> getInputsAndOutputs() {
		return Stream.of(
				Arguments.of(new byte[] {}, ""),
				Arguments.of(new byte[] { 65 }, "41"),
				Arguments.of(new byte[] { 96 }, "60"),
				Arguments.of(new byte[] { 0 }, "00"),
				Arguments.of(new byte[] { 127 }, "7F"),
				Arguments.of(new byte[] { -128 }, "80"),
				Arguments.of(new byte[] { -1 }, "FF"),
				Arguments.of(new byte[] { 65, 0 }, "4100"),
				Arguments.of(new byte[] { 1, 1, 1 }, "010101"),
				Arguments.of(new byte[] { 127, 0, -2, 3 }, "7F00FE03")

		);
	}

	@ParameterizedTest
	@MethodSource("getInputsAndOutputs")
	@DisplayName("base16Encode with valid input gives expected output")
	void base16EncodeWithValidInputGivesExpectedResult(final byte[] input, final String expectedOutput) {
		final String result = base16Service.base16Encode(input);

		assertEquals(expectedOutput, result);
	}

	@ParameterizedTest
	@MethodSource("getInputsAndOutputs")
	@DisplayName("base16Decode with valid inputs gives expected output")
	void base16DecodeWithValidInputGivesExpectedResult(final byte[] expectedOutput, final String input) {
		final byte[] result = base16Service.base16Decode(input);

		assertArrayEquals(expectedOutput, result);
	}

	@RepeatedTest(10)
	@DisplayName("base16Encode then base16Decode returns initial value")
	void base16EncodeThenBase16DecodeReturnsInitialValue() {
		final byte[] randomBytes = randomService.randomBytes(16);

		final String string = base16Service.base16Encode(randomBytes);
		final byte[] result = base16Service.base16Decode(string);
		assertArrayEquals(randomBytes, result);
	}
}