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
package ch.post.it.evoting.cryptoprimitives.math;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;
import java.util.regex.Pattern;

import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

class RandomServiceTest {

	// RFC 4648 Table 1, Table 3 and Table 5.
	private static final Pattern base64Alphabet = Pattern.compile("^[A-Za-z0-9+/=]+$");
	private static final Pattern base32Alphabet = Pattern.compile("^[A-Z2-7=]+$");
	private static final Pattern base16Alphabet = Pattern.compile("^[A-F0-9=]+$");
	private final SecureRandom secureRandom = new SecureRandom();
	private final RandomService randomService = new RandomService();

	@RepeatedTest(1000)
	void genRandomIntegerTest() {
		final BigInteger upperBound = BigInteger.valueOf(100);
		final BigInteger randomInteger = randomService.genRandomInteger(upperBound);

		assertTrue(randomInteger.compareTo(upperBound) < 0);
		assertTrue(randomInteger.compareTo(BigInteger.ZERO) >= 0);
	}

	@Test
	void genRandomIntegerWithInvalidUpperBounds() {
		assertThrows(NullPointerException.class, () -> randomService.genRandomInteger(null));
		assertThrows(IllegalArgumentException.class, () -> randomService.genRandomInteger(BigInteger.ZERO));
		final BigInteger minusOne = BigInteger.ONE.negate();
		assertThrows(IllegalArgumentException.class, () -> randomService.genRandomInteger(minusOne));
	}

	@Test
	void genRandomBase16StringTest() {
		final String randomString1 = randomService.genRandomBase16String(6);
		final String randomString2 = randomService.genRandomBase16String(8);
		final String randomString3 = randomService.genRandomBase16String(1);

		assertAll(
				() -> assertEquals(6, randomString1.length()),
				() -> assertEquals(8, randomString2.length()),
				() -> assertEquals(1, randomString3.length())
		);

		// Check that the Strings chars are in the Base16 alphabet.
		assertAll(
				() -> assertTrue(base16Alphabet.matcher(randomString1).matches()),
				() -> assertTrue(base16Alphabet.matcher(randomString2).matches()),
				() -> assertTrue(base16Alphabet.matcher(randomString3).matches())
		);
	}

	@Test
	void genRandomBase16StringInvalidLengthShouldThrow() {
		assertThrows(IllegalArgumentException.class, () -> randomService.genRandomBase16String(0));
	}

	@Test
	void genRandomBase32StringTest() {
		final String randomString1 = randomService.genRandomBase32String(6);
		final String randomString2 = randomService.genRandomBase32String(8);
		final String randomString3 = randomService.genRandomBase32String(1);

		assertAll(
				() -> assertEquals(6, randomString1.length()),
				() -> assertEquals(8, randomString2.length()),
				() -> assertEquals(1, randomString3.length())
		);

		// Check that the Strings chars are in the Base32 alphabet.
		assertAll(
				() -> assertTrue(base32Alphabet.matcher(randomString1).matches()),
				() -> assertTrue(base32Alphabet.matcher(randomString2).matches()),
				() -> assertTrue(base32Alphabet.matcher(randomString3).matches())
		);
	}

	@Test
	void genRandomBase32StringInvalidLengthShouldThrow() {
		assertThrows(IllegalArgumentException.class, () -> randomService.genRandomBase32String(0));
	}

	@Test
	void genRandomBase64StringTest() {
		final String randomString1 = randomService.genRandomBase64String(6);
		final String randomString2 = randomService.genRandomBase64String(8);
		final String randomString3 = randomService.genRandomBase64String(1);

		assertAll(
				() -> assertEquals(6, randomString1.length()),
				() -> assertEquals(8, randomString2.length()),
				() -> assertEquals(1, randomString3.length())
		);

		// Check that the Strings chars are in the Base64 alphabet.
		assertAll(
				() -> assertTrue(base64Alphabet.matcher(randomString1).matches()),
				() -> assertTrue(base64Alphabet.matcher(randomString2).matches()),
				() -> assertTrue(base64Alphabet.matcher(randomString3).matches())
		);
	}

	@Test
	void genRandomBase64StringInvalidLengthShouldThrow() {
		assertThrows(IllegalArgumentException.class, () -> randomService.genRandomBase64String(0));
	}

	@Test
	void genRandomVector() {
		final BigInteger upperBound = BigInteger.valueOf(100);
		final int length = 20;
		final List<ZqElement> randomVector = randomService.genRandomVector(upperBound, length);

		assertEquals(length, randomVector.size());
		assertEquals(0, (int) randomVector.stream().filter(zq -> zq.getValue().compareTo(upperBound) >= 0).count());
		assertEquals(1, randomVector.stream().map(ZqElement::getGroup).distinct().count());
	}

	@Test
	void checkGenRandomVectorParameterChecks() {
		assertThrows(NullPointerException.class, () -> randomService.genRandomVector(null, 1));
		assertThrows(IllegalArgumentException.class, () -> randomService.genRandomVector(BigInteger.ZERO, 1));
		assertThrows(IllegalArgumentException.class, () -> randomService.genRandomVector(BigInteger.ONE, 0));
	}

	@Test
	void randomBytes() {
		final int RANDOM_BYTES_LENGTH_NINTY_SIX = 96;
		final int RANDOM_BYTES_LENGTH_ZERO = 0;

		byte[] randomBytes = randomService.randomBytes(RANDOM_BYTES_LENGTH_NINTY_SIX);
		assertEquals(RANDOM_BYTES_LENGTH_NINTY_SIX, randomBytes.length);

		randomBytes = randomService.randomBytes(RANDOM_BYTES_LENGTH_ZERO);
		assertEquals(RANDOM_BYTES_LENGTH_ZERO, randomBytes.length);
	}

	@Test
	void genRandomCodeWithCodeLength0Throws() {
		Exception exception = assertThrows(IllegalArgumentException.class, () -> randomService.genRandomBase10String(0));

		String expectedMessage = "Length of the code must be greater than zero";
		String actualMessage = exception.getMessage();

		assertEquals(expectedMessage, actualMessage);
	}

	@Test
	void genRandomCodeWithCodeLength1() {
		String code = randomService.genRandomBase10String(1);

		assertEquals(1, code.length(), "code should be of size 1");
		assertTrue(code.matches("[0-9]"), "code should match [0-9]: " + code);
	}

	@RepeatedTest(value = 10)
	void genRandomCodeWithRandomCodeLength() {
		final int codeLength = secureRandom.nextInt(2000) + 1;

		String code = randomService.genRandomBase10String(codeLength);

		assertEquals(codeLength, code.length(), "code should be of size " + codeLength);
		assertTrue(code.matches("[0]*[0-9]*"), "code should match [0]*[0-9]*: " + code);
	}
}
