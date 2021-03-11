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

import java.math.BigInteger;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;

class GqElementTest {

	private static BigInteger g;

	private static GqGroup group;
	private static GqGroupGenerator groupGenerator;

	@BeforeAll
	static void setUp() {
		BigInteger q = new BigInteger("11");
		BigInteger p = new BigInteger("23");
		g = new BigInteger("2");
		group = new GqGroup(p, q, g);
		groupGenerator = new GqGroupGenerator(group);
	}

	//Object creation

	@Test
	void givenAValueWhenAGroupElementIsCreatedWithThatValueThenHasThatValue() {
		BigInteger value = new BigInteger("2");
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
		BigInteger value = new BigInteger("-1");
		assertThrows(IllegalArgumentException.class, () -> GqElement.create(value, group));
	}

	@Test
	void whenCreateAnElementWithValueGreaterThanPThenError() {
		BigInteger value = new BigInteger("24");
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
		BigInteger value = new BigInteger("16");
		BigInteger expectedInverseValue = new BigInteger("13");
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
		BigInteger value1 = new BigInteger("3");
		GqElement element1 = GqElement.create(value1, group);
		assertThrows(NullPointerException.class, () -> element1.multiply(null));
	}

	@Test
	void givenTwoElementsFromDifferentGroupsWhenMultiplyThenException() {
		BigInteger value1 = new BigInteger("3");
		BigInteger value2 = new BigInteger("2");

		GqElement element1 = GqElement.create(value1, group);
		GqElement element2 = GqElement.create(value2, new GqGroup(new BigInteger("7"), new BigInteger("3"), g));
		assertThrows(IllegalArgumentException.class, () -> element1.multiply(element2));
	}

	@Test
	void givenTwoElementsWhenMultipliedThenSucceeds() {
		BigInteger value1 = new BigInteger("3");
		BigInteger value2 = new BigInteger("4");
		BigInteger expectedResult = new BigInteger("12");

		multiplyAndAssert(value1, value2, expectedResult);
	}

	@Test
	void givenAnElementWithValueOneWhenMultipliedWithASecondElementThenTheResultIsSecondElement() {
		BigInteger value1 = new BigInteger("2");
		BigInteger value2 = BigInteger.ONE;
		BigInteger expectedResult = new BigInteger("2");

		multiplyAndAssert(value1, value2, expectedResult);
	}

	@Test
	void givenTwoElementWhenMultipliedThenTheResultIsGreaterThanP() {
		BigInteger value1 = new BigInteger("12");
		BigInteger value2 = new BigInteger("13");
		BigInteger expectedResult = new BigInteger("18");

		multiplyAndAssert(value1, value2, expectedResult);
	}

	//Exponentiation

	@Test
	void givenElementAndNullExponentWhenExponentiateThenException() {

		BigInteger value1 = new BigInteger("3");
		GqElement element = GqElement.create(value1, group);

		assertThrows(NullPointerException.class, () -> element.exponentiate(null));
	}

	@Test
	void givenElementAndExponentFromDifferentGroupsWhenExponentiateThenException() {

		BigInteger value1 = new BigInteger("3");
		GqElement element = GqElement.create(value1, group);

		ZqGroup exponentGroup = new ZqGroup(BigInteger.valueOf(3));
		BigInteger exponentValue = BigInteger.valueOf(2);
		ZqElement exponent = ZqElement.create(exponentValue, exponentGroup);

		assertThrows(IllegalArgumentException.class, () -> element.exponentiate(exponent));
	}

	@Test
	void givenAnExponentWithValueZeroWhenExponentiateWithItThenResultIsOne() {
		BigInteger value = new BigInteger("16");
		BigInteger exponentValue = BigInteger.ZERO;
		BigInteger expectedResult = BigInteger.ONE;

		exponentiateAndAssert(value, exponentValue, expectedResult);
	}

	@Test
	void givenElementAndExponentWhenExponentiateThenSucceeds() {
		BigInteger value = new BigInteger("2");
		BigInteger exponentValue = new BigInteger("4");
		BigInteger expectedResult = new BigInteger("16");

		exponentiateAndAssert(value, exponentValue, expectedResult);
	}

	@Test
	void givenElementAndExponentWhenExponentiationThenResultGreaterThanQ() {
		BigInteger value = new BigInteger("13");
		BigInteger exponentValue = new BigInteger("5");
		BigInteger expectedResult = new BigInteger("4");

		exponentiateAndAssert(value, exponentValue, expectedResult);
	}

	@Test
	void testExponentiateWithANullElement() {
		GqElement element = GqElement.create(BigInteger.valueOf(1), group);

		assertThrows(NullPointerException.class, () -> element.exponentiate(null));
	}

	//Equals

	@Test
	void testEquals() {

		GqElement element1_value1_q11 = GqElement.create(BigInteger.ONE, group);
		GqElement element2_value1_q11 = GqElement.create(BigInteger.ONE, group);

		GqElement element3_value2_q11 = GqElement.create(new BigInteger("2"), group);

		GqGroup otherGroup_g4_q3 = new GqGroup(new BigInteger("7"), new BigInteger("3"), new BigInteger("2"));
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
}
