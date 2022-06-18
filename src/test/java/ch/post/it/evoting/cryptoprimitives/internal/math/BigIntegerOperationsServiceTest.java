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

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class BigIntegerOperationsServiceTest {

	private static final BigInteger MINUS_ONE = BigInteger.valueOf(-1L);
	private static final BigInteger ZERO = BigInteger.ZERO;
	private static final BigInteger ONE = BigInteger.ONE;
	private static final BigInteger TWO = BigInteger.valueOf(2L);
	private static final BigInteger THREE = BigInteger.valueOf(3L);
	private static final BigInteger FOUR = BigInteger.valueOf(4L);
	private static final BigInteger FIVE = BigInteger.valueOf(5L);
	private static final BigInteger SIX = BigInteger.valueOf(6L);
	private static final BigInteger SEVEN = BigInteger.valueOf(7L);
	private static final BigInteger EIGHT = BigInteger.valueOf(8L);
	private static final BigInteger NINE = BigInteger.valueOf(9L);
	private static final BigInteger TWENTY_ONE = BigInteger.valueOf(21L);

	private static List<BigInteger> bases;
	private static List<BigInteger> exponents;

	@BeforeAll
	static void setUpAll() {
		bases = new ArrayList<>();
		bases.add(TWO);
		bases.add(THREE);

		exponents = new ArrayList<>();
		exponents.add(FIVE);
		exponents.add(SIX);
	}

	// provides arguments for null tests
	static Stream<Arguments> createArgumentsProvider() {
		return Stream.of(
				Arguments.of(null, THREE, SEVEN),
				Arguments.of(TWO, null, SEVEN),
				Arguments.of(TWO, THREE, null)
		);
	}

	@Test
	void modMultiplyTest() {
		assertEquals(SIX, BigIntegerOperationsService.modMultiply(TWO, THREE, SEVEN));
		assertEquals(SIX, BigIntegerOperationsService.modMultiply(THREE.negate(), FIVE, SEVEN));

	}

	@ParameterizedTest(name = "n1 = {0}, n2 = {1} and modulus = {2} throws NullPointerException")
	@MethodSource("createArgumentsProvider")
	@DisplayName("modMultiply with null parameters")
	void modMultiplyNullArguments(BigInteger n1, BigInteger n2, BigInteger modulus) {
		assertThrows(NullPointerException.class, () -> BigIntegerOperationsService.modMultiply(n1, n2, modulus));
	}

	@Test
	void modMultiplyInvalidModulus() {
		assertAll(
				() -> assertThrows(IllegalArgumentException.class, () -> BigIntegerOperationsService.modMultiply(TWO, SIX, ONE)),
				() -> assertThrows(IllegalArgumentException.class, () -> BigIntegerOperationsService.modMultiply(TWO, SIX, ZERO)),
				() -> assertThrows(IllegalArgumentException.class, () -> BigIntegerOperationsService.modMultiply(TWO, SIX, MINUS_ONE))
		);
	}

	@RepeatedTest(1000)
	void checkModExponentiate() {
		assertAll(
				() -> assertEquals(ONE, BigIntegerOperationsService.modExponentiate(TWO, THREE, SEVEN)),
				() -> assertEquals(SIX, BigIntegerOperationsService.modExponentiate(TWO.negate(), THREE, SEVEN)),
				() -> assertEquals(ONE, BigIntegerOperationsService.modExponentiate(TWO, THREE.negate(), SEVEN))
		);
	}

	@ParameterizedTest(name = "base = {0}, exponent = {1} and modulus = {2} throws NullPointerException")
	@MethodSource("createArgumentsProvider")
	@DisplayName("modExponentiate with null parameters")
	void modExponentiateNullArguments(BigInteger base, BigInteger exponent, BigInteger modulus) {
		assertThrows(NullPointerException.class, () -> BigIntegerOperationsService.modExponentiate(base, exponent, modulus));
	}

	@Test
	void modExponentiateInvalidModulus() {
		assertAll(
				() -> assertThrows(IllegalArgumentException.class, () -> BigIntegerOperationsService.modExponentiate(TWO, SIX, ONE)),
				() -> assertThrows(IllegalArgumentException.class, () -> BigIntegerOperationsService.modExponentiate(TWO, SIX, ZERO)),
				() -> assertThrows(IllegalArgumentException.class, () -> BigIntegerOperationsService.modExponentiate(TWO, SIX, MINUS_ONE)),
				() -> assertThrows(IllegalArgumentException.class, () -> BigIntegerOperationsService.modExponentiate(TWO, SIX, TWO))
		);
	}

	@Test
	void modExponentiateBaseModulusNotRelativelyPrime() {
		assertEquals(EIGHT, BigIntegerOperationsService.modExponentiate(TWO, THREE, NINE));
		final BigInteger negativeThree = THREE.negate();
		assertThrows(IllegalArgumentException.class, () -> BigIntegerOperationsService.modExponentiate(THREE, negativeThree, NINE));
	}

	@Test
	void checkMultiModExp() {
		List<BigInteger> basesOneNegative = new ArrayList<>();
		basesOneNegative.add(TWO);
		basesOneNegative.add(THREE.negate());

		List<BigInteger> exponentsOneNegative = new ArrayList<>();
		exponentsOneNegative.add(FIVE);
		exponentsOneNegative.add(SIX.negate());

		assertAll(
				() -> assertEquals(FOUR, BigIntegerOperationsService.multiModExp(bases, exponents, SEVEN)),
				() -> assertEquals(FOUR, BigIntegerOperationsService.multiModExp(basesOneNegative, exponents, SEVEN)),
				() -> assertEquals(FOUR, BigIntegerOperationsService.multiModExp(bases, exponentsOneNegative, SEVEN)),
				() -> assertEquals(FOUR, BigIntegerOperationsService.multiModExp(basesOneNegative, exponentsOneNegative, SEVEN))
		);
	}

	@Test
	void multiModExpNullArguments() {
		assertAll(
				() -> assertThrows(NullPointerException.class, () -> BigIntegerOperationsService.multiModExp(null, exponents, SEVEN)),
				() -> assertThrows(NullPointerException.class, () -> BigIntegerOperationsService.multiModExp(bases, null, SEVEN)),
				() -> assertThrows(NullPointerException.class, () -> BigIntegerOperationsService.multiModExp(bases, exponents, null))
		);
	}

	@Test
	void multiModExpInvalidModulus() {
		assertAll(
				() -> assertThrows(IllegalArgumentException.class, () -> BigIntegerOperationsService.multiModExp(bases, exponents, ONE)),
				() -> assertThrows(IllegalArgumentException.class, () -> BigIntegerOperationsService.multiModExp(bases, exponents, ZERO)),
				() -> assertThrows(IllegalArgumentException.class, () -> BigIntegerOperationsService.multiModExp(bases, exponents, MINUS_ONE))
		);
	}

	@Test
	void multiModExpBasesModulusNotRelativelyPrime() {
		assertEquals(ZERO, BigIntegerOperationsService.multiModExp(bases, exponents, NINE));

		List<BigInteger> exponentsOneNegative = new ArrayList<>();
		exponentsOneNegative.add(FIVE);
		exponentsOneNegative.add(SIX.negate());
		assertThrows(IllegalArgumentException.class, () -> BigIntegerOperationsService.multiModExp(bases, exponentsOneNegative, NINE));
	}

	@Test
	void multiModExpEmptyBases() {
		List<BigInteger> emptyList = Collections.emptyList();
		assertThrows(IllegalArgumentException.class, () -> BigIntegerOperationsService.multiModExp(emptyList, exponents, SEVEN));
	}

	@Test
	void multiModExpEmptyExponents() {
		List<BigInteger> emptyList = Collections.emptyList();
		assertThrows(IllegalArgumentException.class, () -> BigIntegerOperationsService.multiModExp(bases, emptyList, SEVEN));
	}

	@Test
	void multiModExpBasesDifferentSizeExponents() {
		List<BigInteger> arguments = new ArrayList<>(bases);
		arguments.add(FIVE);
		assertThrows(IllegalArgumentException.class, () -> BigIntegerOperationsService.multiModExp(arguments, exponents, SEVEN));
		assertThrows(IllegalArgumentException.class, () -> BigIntegerOperationsService.multiModExp(bases, arguments, SEVEN));
	}

	@Test
	void checkModInvert() {
		assertEquals(ONE, BigIntegerOperationsService.modInvert(ONE, SEVEN));
		assertEquals(FIVE, BigIntegerOperationsService.modInvert(THREE, SEVEN));
	}

	@Test
	void modInvertNullArguments() {
		assertThrows(NullPointerException.class, () -> BigIntegerOperationsService.modInvert(null, SEVEN));
		assertThrows(NullPointerException.class, () -> BigIntegerOperationsService.modInvert(ONE, null));
	}

	@Test
	void modInvertInvalidModulus() {
		assertAll(
				() -> assertThrows(IllegalArgumentException.class, () -> BigIntegerOperationsService.modInvert(TWO, ONE)),
				() -> assertThrows(IllegalArgumentException.class, () -> BigIntegerOperationsService.modInvert(TWO, ZERO)),
				() -> assertThrows(IllegalArgumentException.class, () -> BigIntegerOperationsService.modInvert(TWO, MINUS_ONE))
		);
	}

	@Test
	void modInvertNonInvertibleElement() {
		assertThrows(IllegalArgumentException.class, () -> BigIntegerOperationsService.modInvert(TWO, SIX));
		assertThrows(IllegalArgumentException.class, () -> BigIntegerOperationsService.modInvert(THREE, SIX));
	}

	@Test
	void jacobiInvalidArguments() {
		assertAll(
				() -> assertThrows(NullPointerException.class, () -> BigIntegerOperationsService.getJacobi(null, null)),
				() -> assertThrows(NullPointerException.class, () -> BigIntegerOperationsService.getJacobi(ZERO, null)),
				() -> assertThrows(NullPointerException.class, () -> BigIntegerOperationsService.getJacobi(null, ONE)),
				() -> assertThrows(IllegalArgumentException.class, () -> BigIntegerOperationsService.getJacobi(ZERO, ZERO)),
				() -> assertThrows(IllegalArgumentException.class, () -> BigIntegerOperationsService.getJacobi(MINUS_ONE, ONE))
		);
	}

	@Test
	void jacobiValidArguments() {
		assertEquals(1, BigIntegerOperationsService.getJacobi(ONE, FIVE));
		assertEquals(1, BigIntegerOperationsService.getJacobi(FIVE, ONE));
		assertEquals(-1, BigIntegerOperationsService.getJacobi(THREE, EIGHT));
		assertEquals(0, BigIntegerOperationsService.getJacobi(TWENTY_ONE, SEVEN));
	}
}
