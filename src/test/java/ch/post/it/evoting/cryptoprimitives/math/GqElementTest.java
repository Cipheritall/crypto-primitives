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
package ch.post.it.evoting.cryptoprimitives.math;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullSource;

import ch.post.it.evoting.cryptoprimitives.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;

class GqElementTest {

	private static BigInteger g;

	private static GqGroup group;
	private static GqGroupGenerator groupGenerator;

	@BeforeAll
	static void setUp() {
		final BigInteger q = BigInteger.valueOf(11);
		final BigInteger p = BigInteger.valueOf(23);
		g = BigInteger.valueOf(2);

		group = new GqGroup(p, q, g);
		groupGenerator = new GqGroupGenerator(group);
	}

	//Object creation

	@Test
	void givenAValueWhenAGroupElementIsCreatedWithThatValueThenHasThatValue() {
		BigInteger value = BigInteger.valueOf(2);
		GqElement element = GqElement.create(value, group);
		assertEquals(value, element.getValue(), "The returned element value is not the expected one");
	}

	@Test
	void whenCreateAnElementWithValueZeroThenError() {
		BigInteger value = BigInteger.ZERO;
		assertThrows(IllegalArgumentException.class, () -> GqElement.create(value, group));
	}

	@Test
	void whenCreateAnElementWithNegativeValueThenError() {
		BigInteger value = BigInteger.valueOf(-1);
		assertThrows(IllegalArgumentException.class, () -> GqElement.create(value, group));
	}

	@Test
	void whenCreateAnElementWithValueGreaterThanPThenError() {
		BigInteger value = BigInteger.valueOf(24);
		assertThrows(IllegalArgumentException.class, () -> GqElement.create(value, group));
	}

	@Test
	void whenCreateAnElementWithNullValueThenError() {
		assertThrows(NullPointerException.class, () -> GqElement.create(null, group));
	}

	@Test
	void whenCreateAnElementWithNullGroupThenError() {
		BigInteger value = BigInteger.ONE;
		assertThrows(NullPointerException.class, () -> GqElement.create(value, null));
	}

	@Test
	void whenCreateAnElementNotMemberOfTheGroupError() {
		BigInteger nonMemberValue = groupGenerator.genNonMemberValue();
		assertThrows(IllegalArgumentException.class, () -> GqElement.create(nonMemberValue, group));
	}

	@Test
	void whenCreateAnElementMemberOfTheGroupNoError() {
		BigInteger memberValue = groupGenerator.genMemberValue();
		GqElement groupMember = GqElement.create(memberValue, group);
		assertTrue(group.isGroupMember(groupMember.getValue()));
	}

	//Inversion

	@Test
	void givenAnElementWhenInvertedThenSucceeds() {
		BigInteger value = BigInteger.valueOf(16);
		BigInteger expectedInverseValue = BigInteger.valueOf(13);
		invertAndAssert(value, expectedInverseValue);
	}

	@Test
	void givenAnElementWithValueOneWhenInvertedThenResultIsOne() {
		BigInteger value = BigInteger.ONE;
		BigInteger expectedInverseValue = BigInteger.ONE;
		invertAndAssert(value, expectedInverseValue);
	}

	//Multiplication

	@Test
	void givenNullElementWhenMultiplyThenException() {
		BigInteger value1 = BigInteger.valueOf(3);
		GqElement element1 = GqElement.create(value1, group);
		assertThrows(NullPointerException.class, () -> element1.multiply(null));
	}

	@Test
	void givenTwoElementsFromDifferentGroupsWhenMultiplyThenException() {
		BigInteger value1 = BigInteger.valueOf(3);
		BigInteger value2 = BigInteger.valueOf(2);

		GqElement element1 = GqElement.create(value1, group);
		GqElement element2 = GqElement.create(value2, new GqGroup(BigInteger.valueOf(7), BigInteger.valueOf(3), g));
		assertThrows(IllegalArgumentException.class, () -> element1.multiply(element2));
	}

	@Test
	void givenTwoElementsWhenMultipliedThenSucceeds() {
		BigInteger value1 = BigInteger.valueOf(3);
		BigInteger value2 = BigInteger.valueOf(4);
		BigInteger expectedResult = BigInteger.valueOf(12);

		multiplyAndAssert(value1, value2, expectedResult);
	}

	@Test
	void givenAnElementWithValueOneWhenMultipliedWithASecondElementThenTheResultIsSecondElement() {
		BigInteger value1 = BigInteger.valueOf(2);
		BigInteger value2 = BigInteger.ONE;
		BigInteger expectedResult = BigInteger.valueOf(2);

		multiplyAndAssert(value1, value2, expectedResult);
	}

	@Test
	void givenTwoElementWhenMultipliedThenTheResultIsGreaterThanP() {
		BigInteger value1 = BigInteger.valueOf(12);
		BigInteger value2 = BigInteger.valueOf(13);
		BigInteger expectedResult = BigInteger.valueOf(18);

		multiplyAndAssert(value1, value2, expectedResult);
	}

	//Exponentiation

	@Test
	void givenElementAndNullExponentWhenExponentiateThenException() {

		BigInteger value1 = BigInteger.valueOf(3);
		GqElement element = GqElement.create(value1, group);

		assertThrows(NullPointerException.class, () -> element.exponentiate(null));
	}

	@Test
	void givenElementAndExponentFromDifferentGroupsWhenExponentiateThenException() {

		BigInteger value1 = BigInteger.valueOf(3);
		GqElement element = GqElement.create(value1, group);

		ZqGroup exponentGroup = new ZqGroup(BigInteger.valueOf(3));
		BigInteger exponentValue = BigInteger.valueOf(2);
		ZqElement exponent = ZqElement.create(exponentValue, exponentGroup);

		assertThrows(IllegalArgumentException.class, () -> element.exponentiate(exponent));
	}

	@Test
	void givenAnExponentWithValueZeroWhenExponentiateWithItThenResultIsOne() {
		BigInteger value = BigInteger.valueOf(16);
		BigInteger exponentValue = BigInteger.ZERO;
		BigInteger expectedResult = BigInteger.ONE;

		exponentiateAndAssert(value, exponentValue, expectedResult);
	}

	@Test
	void givenElementAndExponentWhenExponentiateThenSucceeds() {
		BigInteger value = BigInteger.valueOf(2);
		BigInteger exponentValue = BigInteger.valueOf(4);
		BigInteger expectedResult = BigInteger.valueOf(16);

		exponentiateAndAssert(value, exponentValue, expectedResult);
	}

	@Test
	void givenElementAndExponentWhenExponentiationThenResultGreaterThanQ() {
		BigInteger value = BigInteger.valueOf(13);
		BigInteger exponentValue = BigInteger.valueOf(5);
		BigInteger expectedResult = BigInteger.valueOf(4);

		exponentiateAndAssert(value, exponentValue, expectedResult);
	}

	@Test
	void testExponentiateWithANullElement() {
		GqElement element = GqElement.create(BigInteger.ONE, group);

		assertThrows(NullPointerException.class, () -> element.exponentiate(null));
	}

	@Test
	void testInverseOfOneEqualsOne() {
		GqElement one = group.getIdentity();
		assertEquals(one, one.inverse());
	}

	@Test
	void testInverse() {
		for (int i = 1; i < group.getQ().intValueExact(); i++) {
			ZqElement exponent = ZqElement.create(i, ZqGroup.sameOrderAs(group));
			GqElement element = group.getGenerator().exponentiate(exponent);
			assertEquals(group.getIdentity(), element.multiply(element.inverse()));
		}
	}

	//Equals

	@Test
	void testEquals() {

		GqElement element1_value1_q11 = GqElement.create(BigInteger.ONE, group);
		GqElement element2_value1_q11 = GqElement.create(BigInteger.ONE, group);

		GqElement element3_value2_q11 = GqElement.create(BigInteger.valueOf(2), group);

		GqGroup otherGroup_g4_q3 = new GqGroup(BigInteger.valueOf(7), BigInteger.valueOf(3), BigInteger.valueOf(2));
		GqElement element4_value1_q13 = GqElement.create(BigInteger.ONE, otherGroup_g4_q3);

		assertAll(
				() -> assertEquals(element1_value1_q11, element2_value1_q11),
				() -> assertNotEquals(element1_value1_q11, element3_value2_q11),
				() -> assertNotEquals(element1_value1_q11, element4_value1_q13),
				() -> assertNotEquals(element3_value2_q11, element4_value1_q13)
		);
	}

	/**
	 * Exponentiates an element by an exponent and asserts the expected result.
	 *
	 * @param elementValue   The group element value to set.
	 * @param exponentValue  The exponent value to set.
	 * @param expectedResult The expected result of the exponentiation.
	 */
	private void exponentiateAndAssert(final BigInteger elementValue, final BigInteger exponentValue, final BigInteger expectedResult) {
		GqElement element = GqElement.create(elementValue, group);
		ZqElement exponent = ZqElement.create(exponentValue, ZqGroup.sameOrderAs(group));
		GqElement result = element.exponentiate(exponent);
		assertEquals(expectedResult, result.getValue(), "The result of the exponentiation is not the expected.");
	}

	/**
	 * Multiply two group elements with the values {@code value1} and {@code value2}. Then asserts that the result has the value {@code
	 * expectedResult}.
	 *
	 * @param value1         First element to multiply.
	 * @param value2         Second element to multiply.
	 * @param expectedResult The expected result of the {@code value1 * value2}.
	 */
	private void multiplyAndAssert(final BigInteger value1, final BigInteger value2, final BigInteger expectedResult) {
		GqElement element1 = GqElement.create(value1, group);
		GqElement element2 = GqElement.create(value2, group);
		GqElement result = element1.multiply(element2);
		assertEquals(expectedResult, result.getValue(), "The multiplication result is not the expected one");
	}

	/**
	 * Inverts the element with the value {@code elementValue}, and checks whether the result is the {@code expectedInverseValue}.
	 *
	 * @param elementValue         The value of the element to invert.
	 * @param expectedInverseValue The expected result of the invert operation of the element with value {@code elementValue}.
	 */
	private void invertAndAssert(final BigInteger elementValue, final BigInteger expectedInverseValue) {
		GqElement element = GqElement.create(elementValue, group);
		GqElement inverse = element.invert();
		assertEquals(expectedInverseValue, inverse.getValue(), "The returned element is not the inverse");
	}

	@ParameterizedTest(name = "input hash service is {0}.")
	@NullSource
	@DisplayName("calling hashAndSquare on a valid gqElement with a null hash service throws an exception.")
	void nullCheckTest(final HashService nullHashService) {

		final GqElement gqElement = GqElement.create(g, group);

		assertThrows(NullPointerException.class, () -> gqElement.hashAndSquare(nullHashService));
	}

	@Test
	@DisplayName("calling hashAndSquare on a valid element with a hash service with a too big hash length throws an exception.")
	void hashAndSquareWithIncompatibleHashService() throws NoSuchAlgorithmException {
		final HashService hashService = new HashService(MessageDigest.getInstance("SHA-256"));
		final GqElement gqElement = GqElement.create(g, group);

		assertThrows(IllegalArgumentException.class, () -> gqElement.hashAndSquare(hashService));
	}

	@ParameterizedTest
	@MethodSource("onValidGqElementReturnsExpectedResultTestSource")
	@DisplayName("calling hashAndSquare on a valid gqElement with an hash call returning a specific mocked value returns the expected result.")
	void onValidGqElementReturnsExpectedResultTest(final byte[] mockedHash, final BigInteger expectedResult) throws IOException {

		final HashService hashService = mock(HashService.class);
		when(hashService.recursiveHash(any())).thenReturn(mockedHash);

		final GqGroup largeGqGroup = GroupTestData.getLargeGqGroup();

		final GqElement gqElement = GqElement.create(g, largeGqGroup);

		assertEquals(expectedResult, gqElement.hashAndSquare(hashService).getValue());
	}

	private static Stream<Arguments> onValidGqElementReturnsExpectedResultTestSource() {

		return Stream.of(
				Arguments.of(new byte[] { 0b10 }, BigInteger.valueOf(9)),
				Arguments.of(new byte[] { 0x00 }, BigInteger.ONE),
				Arguments.of(new byte[] {
								0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
								0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
								0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
								0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
						new BigInteger("134078079299425970995740249982058461274793658205923933777235614437217640300735469768018742981669034276900318"
								+ "58186486050853753882811946569946433649006084096"))
		);
	}
}
