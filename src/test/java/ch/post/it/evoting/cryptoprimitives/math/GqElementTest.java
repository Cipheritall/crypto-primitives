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

import static ch.post.it.evoting.cryptoprimitives.math.GqElement.GqElementFactory;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.util.Set;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

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

	//Inversion

	@Test
	void givenAnElementWhenMultipliedWithItsInverseThenResultIsOne() {
		for (int i = 1; i < group.getQ().intValueExact(); i++) {
			ZqElement exponent = ZqElement.create(i, ZqGroup.sameOrderAs(group));
			GqElement element = group.getGenerator().exponentiate(exponent);
			assertEquals(group.getIdentity(), element.multiply(element.invert()));
		}
	}

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
		GqElement element1 = GqElementFactory.fromValue(value1, group);
		assertThrows(NullPointerException.class, () -> element1.multiply(null));
	}

	@Test
	void givenTwoElementsFromDifferentGroupsWhenMultiplyThenException() {
		BigInteger value1 = BigInteger.valueOf(3);
		BigInteger value2 = BigInteger.valueOf(2);

		GqElement element1 = GqElementFactory.fromValue(value1, group);
		GqElement element2 = GqElementFactory.fromValue(value2, new GqGroup(BigInteger.valueOf(7), BigInteger.valueOf(3), g));
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
		GqElement element = GqElementFactory.fromValue(value1, group);

		assertThrows(NullPointerException.class, () -> element.exponentiate(null));
	}

	@Test
	void givenElementAndExponentFromDifferentGroupsWhenExponentiateThenException() {

		BigInteger value1 = BigInteger.valueOf(3);
		GqElement element = GqElementFactory.fromValue(value1, group);

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
		GqElement element = GqElementFactory.fromValue(BigInteger.ONE, group);

		assertThrows(NullPointerException.class, () -> element.exponentiate(null));
	}

	@Test
	void testDivideByNullArgumentThrows() {
		GqElement element = GqElementFactory.fromValue(BigInteger.ONE, group);

		assertThrows(NullPointerException.class, () -> element.divide(null));
	}

	@Test
	void testDivideWithDivisorFromDifferentGroupThrows() {
		GqElement element = GqElementFactory.fromValue(BigInteger.ONE, group);
		GqElement element2 = GqElementFactory.fromValue(BigInteger.ONE, new GqGroup(BigInteger.valueOf(7), BigInteger.valueOf(3), g));
		assertThrows(IllegalArgumentException.class, () -> element.divide(element2));
	}

	@Test
	void testDivideElementByItselfGivesOne() {
		final GroupVector<GqElement, GqGroup> gqElements = groupGenerator.genRandomGqElementVector(10);
		final GqElement identity = group.getIdentity();
		gqElements.forEach(e -> assertEquals(identity, e.divide(e)));
	}

	@Test
	void givenTwoElementsWhenDivideThenSuccess() {
		final GqElement two = GqElementFactory.fromValue(BigInteger.valueOf(2), group);
		final GqElement three = GqElementFactory.fromValue(BigInteger.valueOf(3), group);
		final GqElement four = GqElementFactory.fromValue(BigInteger.valueOf(4), group);
		final GqElement nine = GqElementFactory.fromValue(BigInteger.valueOf(9), group);
		final GqElement twelve = GqElementFactory.fromValue(BigInteger.valueOf(12), group);

		assertEquals(two, four.divide(two));
		assertEquals(four, twelve.divide(three));
		assertEquals(nine, four.divide(three));
	}

	//Equals

	@Test
	void testEquals() {

		GqElement element1_value1_q11 = GqElementFactory.fromValue(BigInteger.ONE, group);
		GqElement element2_value1_q11 = GqElementFactory.fromValue(BigInteger.ONE, group);

		GqElement element3_value2_q11 = GqElementFactory.fromValue(BigInteger.valueOf(2), group);

		GqGroup otherGroup_g4_q3 = new GqGroup(BigInteger.valueOf(7), BigInteger.valueOf(3), BigInteger.valueOf(2));
		GqElement element4_value1_q13 = GqElementFactory.fromValue(BigInteger.ONE, otherGroup_g4_q3);

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
		GqElement element = GqElementFactory.fromValue(elementValue, group);
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
		GqElement element1 = GqElementFactory.fromValue(value1, group);
		GqElement element2 = GqElementFactory.fromValue(value2, group);
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
		GqElement element = GqElementFactory.fromValue(elementValue, group);
		GqElement inverse = element.invert();
		assertEquals(expectedInverseValue, inverse.getValue(), "The returned element is not the inverse");
	}
}
