/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.math;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class ZqElementTest {

	private static ZqGroup smallQGroup;
	private static ZqGroup largeQGroup;
	private static BigInteger smallQGroupMember;
	private static BigInteger largeQGoupMember;

	@BeforeAll
	static void setUp() {

		smallQGroup = new ZqGroup(BigInteger.valueOf(11));

		smallQGroupMember = BigInteger.valueOf(2);

		largeQGroup = new ZqGroup(new BigInteger(
				"12939396283335421049921068858211433233126495514407886569514225839757682339812461790679331327844644602883220990119774411868903477"
						+
						"19850970560112206096787622837469088478251583519395743196778894805821282742465329909275399786894625491980847224803685372266"
						+
						"94030507127336944889687445102283918380513102809853223420079343830140400246864249360575261041072197363016777415478200207577"
						+
						"30425737985559136062566612003974844221840214834045656737059437540810373459953783841199104522171826073664311433417300419939"
						+
						"05714250940923155511355580701633572104273292197035454235983393288056275740012167103086634201440132309660110514958956970530"
						+ "3"));

		largeQGoupMember = new BigInteger(
				"23337993065784550228812110720552652305178266477392633588884900695706615523553977368516877521940228584865573144621632575456086035"
						+
						"44011891370789571610936664154174680840991717947829295213927339653106002172998547312136859057411022087014982249515151970621"
						+
						"03995699012980278133831048916979301493412582679624908502978757946220684184254735784551873442326984628290840105853248774203"
						+
						"43904740081787639502967515631687068869545665294697583750184911025514712871193837246483893950501015755683415509019863976071"
						+
						"64932596862361756821986474438970956308794938908025297141971163638098610004787140454837111247269481459777298855888748030824"
		);
	}

	@Test
	void givenNullValueWhenAttemptToCreateExponentThenException() {
		assertThrows(NullPointerException.class, () -> ZqElement.create(null, smallQGroup));
	}

	@Test
	void givenNullGroupAndValidValueWhenAttemptToCreateExponentThenException() {
		assertThrows(NullPointerException.class, () -> ZqElement.create(BigInteger.TEN, null));
	}

	@Test
	void givenANonRandomExponentValueLessThanQGetExponentValue() {
		BigInteger exponentValue = new BigInteger("1");
		ZqElement exponent = ZqElement.create(exponentValue, smallQGroup);

		assertEquals(exponentValue, exponent.getValue(), "The exponent value is not the expected one");
	}

	@Test
	void givenANegativeValueShouldThrow() {
		BigInteger value = BigInteger.valueOf(-1);
		assertThrows(IllegalArgumentException.class, () -> ZqElement.create(value, smallQGroup));
	}

	@Test
	void givenAValueEqualToQShouldThrow() {
		BigInteger value = smallQGroup.getQ();
		assertThrows(IllegalArgumentException.class, () -> ZqElement.create(value, smallQGroup));
	}

	@Test
	void givenAValueAboveQShouldThrow() {
		BigInteger value = smallQGroup.getQ().add(BigInteger.TEN);
		assertThrows(IllegalArgumentException.class, () -> ZqElement.create(value, smallQGroup));
	}

	@Test
	void givenAnExponentWhenGetQThenExpectedQReturned() {
		BigInteger exponentValue = new BigInteger("2");
		BigInteger expectedQ = new BigInteger("11");
		ZqElement exponent = ZqElement.create(exponentValue, smallQGroup);

		assertEquals(expectedQ, exponent.getGroup().getQ(), "The q is not the expected one");
	}

	@Test
	void givenExponentsDifferentGroupsWhenAddThenException() {
		ZqElement exponent1 = ZqElement.create(smallQGroupMember, smallQGroup);
		ZqElement exponent2 = ZqElement.create(largeQGoupMember, largeQGroup);

		assertThrows(IllegalArgumentException.class, () -> exponent1.add(exponent2));
	}

	@Test
	void givenNullExponentsWhenAddThenException() {
		ZqElement exponent1 = ZqElement.create(smallQGroupMember, smallQGroup);

		assertThrows(NullPointerException.class, () -> exponent1.add(null));
	}

	@Test
	void givenTwoExponentsWhenAddedThenLessThanQ() {
		BigInteger exponent1Value = new BigInteger("2");
		BigInteger exponent2Value = new BigInteger("3");
		BigInteger expectedResult = new BigInteger("5");

		addExponentsAndAssert(exponent1Value, exponent2Value, expectedResult);
	}

	@Test
	void givenTwoExponentsWhenAddedThenEqualsToQ() {
		BigInteger exponent1Value = new BigInteger("5");
		BigInteger exponent2Value = new BigInteger("6");
		BigInteger expectedResult = BigInteger.ZERO;

		addExponentsAndAssert(exponent1Value, exponent2Value, expectedResult);
	}

	@Test
	void givenTwoExponentsWhenAddedThenGreaterThanQ() {
		BigInteger exponent1Value = BigInteger.TEN;
		BigInteger exponent2Value = new BigInteger("2");
		BigInteger expectedResult = BigInteger.ONE;

		addExponentsAndAssert(exponent1Value, exponent2Value, expectedResult);
	}

	@Test
	void givenTwoEqualExponentsWhenAddedThenGreaterThanQ() {
		BigInteger exponent1Value = BigInteger.TEN;
		BigInteger exponent2Value = BigInteger.TEN;
		BigInteger expectedResult = new BigInteger("9");

		addExponentsAndAssert(exponent1Value, exponent2Value, expectedResult);
	}

	@Test
	void givenTwoExponentsOneEqualToZeroWhenAddedThenSucceeds() {
		BigInteger exponent1Value = BigInteger.ZERO;
		BigInteger exponent2Value = new BigInteger("4");
		BigInteger expectedResult = new BigInteger("4");

		addExponentsAndAssert(exponent1Value, exponent2Value, expectedResult);
	}

	@Test
	void givenAnExponentWithValueZeroWhenNegatedThenResultIsZero() {
		BigInteger exponentValue = BigInteger.ZERO;
		BigInteger expectedResult = BigInteger.ZERO;

		negateExponentAndAssert(exponentValue, expectedResult);
	}

	@Test
	void givenAnExponentLessThanQWhenNegatedThenSucceeds() {
		BigInteger exponentValue = new BigInteger("9");
		BigInteger expectedResult = new BigInteger("2");

		negateExponentAndAssert(exponentValue, expectedResult);
	}

	@Test
	void givenTwoExponentsWhenSubtractedResultIsPositive() {
		BigInteger exponent1Value = new BigInteger("3");
		BigInteger exponent2Value = new BigInteger("2");
		BigInteger expectedResult = BigInteger.ONE;

		subtractExponentsAndAssert(exponent1Value, exponent2Value, expectedResult);
	}

	@Test
	void givenTwoExponentsWhenSubtractedResultIsZero() {
		BigInteger exponent1Value = BigInteger.TEN;
		BigInteger exponent2Value = BigInteger.TEN;
		BigInteger expectedResult = BigInteger.ZERO;

		subtractExponentsAndAssert(exponent1Value, exponent2Value, expectedResult);
	}

	@Test
	void givenTwoExponentsWhenSubtractedResultIsNegative() {
		BigInteger exponent1Value = new BigInteger("2");
		BigInteger exponent2Value = new BigInteger("3");
		BigInteger expectedResult = BigInteger.TEN;

		subtractExponentsAndAssert(exponent1Value, exponent2Value, expectedResult);
	}

	@Test
	void givenAnExponentWhenSubtractedZeroThenResultIsTheExponent() {
		BigInteger exponent1Value = new BigInteger("4");
		BigInteger exponent2Value = BigInteger.ZERO;
		BigInteger expectedResult = new BigInteger("4");

		subtractExponentsAndAssert(exponent1Value, exponent2Value, expectedResult);
	}

	@Test
	void givenAnExponentWhenMultipliedSmallThenResultIsCorrect() {
		BigInteger exponent1Value = BigInteger.valueOf(2);
		BigInteger exponent2Value = BigInteger.valueOf(3);
		BigInteger expectedResult = BigInteger.valueOf(6);

		multiplyExponentsAndAssert(exponent1Value, exponent2Value, expectedResult);
	}

	@Test
	void givenAnExponentWhenMultipliedBigThenResultIsCorrect() {
		BigInteger exponent1Value = BigInteger.valueOf(2);
		BigInteger exponent2Value = BigInteger.valueOf(6);
		BigInteger expectedResult = BigInteger.ONE;

		multiplyExponentsAndAssert(exponent1Value, exponent2Value, expectedResult);
	}

	@Test
	void givenAnExponentWhenMultipliedOneThenResultIsZero() {
		BigInteger exponent1Value = BigInteger.valueOf(2);
		BigInteger exponent2Value = BigInteger.ONE;
		BigInteger expectedResult = BigInteger.valueOf(2);

		multiplyExponentsAndAssert(exponent1Value, exponent2Value, expectedResult);
	}

	@Test
	void givenAnExponentWhenMultipliedZeroThenResultIsZero() {
		BigInteger exponent1Value = BigInteger.valueOf(2);
		BigInteger exponent2Value = BigInteger.ZERO;
		BigInteger expectedResult = BigInteger.ZERO;

		multiplyExponentsAndAssert(exponent1Value, exponent2Value, expectedResult);
	}

	@Test
	void whenExponentiatedNullThenThrow() {
		final ZqElement element = ZqElement.create(smallQGroupMember, smallQGroup);
		assertThrows(NullPointerException.class, () -> element.exponentiate(null));
	}

	@Test
	void whenExponentiatedNegativeThrow() {
		final ZqElement element = ZqElement.create(smallQGroupMember, smallQGroup);
		final BigInteger minusOne = BigInteger.valueOf(-1);
		assertThrows(IllegalArgumentException.class, () -> element.exponentiate(minusOne));
	}

	@Test
	void whenExponentiatedZeroThenResultIsOne() {
		exponentiateAndAssert(smallQGroupMember, BigInteger.ZERO, BigInteger.ONE);
	}

	@Test
	void whenExponentiatedSmallThenResultIsCorrect() {
		exponentiateAndAssert(smallQGroupMember, BigInteger.valueOf(6), BigInteger.valueOf(9));
	}

	@Test
	void testEquals() {
		ZqGroup groupOrder11 = new ZqGroup(BigInteger.valueOf(11));
		ZqGroup groupOrder12 = new ZqGroup(BigInteger.valueOf(12));
		BigInteger value = BigInteger.TEN;

		ZqElement same1 = ZqElement.create(value, groupOrder11);
		ZqElement same2 = ZqElement.create(value, groupOrder11);

		ZqElement differentValueSameQ = ZqElement.create(BigInteger.valueOf(7), groupOrder11);
		ZqElement sameValueDifferentQ = ZqElement.create(value, groupOrder12);

		assertAll(
				() -> assertEquals(same1, same2),
				() -> assertNotEquals(same1, differentValueSameQ),
				() -> assertNotEquals(differentValueSameQ, sameValueDifferentQ),
				() -> assertNotEquals(same1, sameValueDifferentQ)
		);
	}

	/**
	 * Create the exponents with the given values, and add them. Then assert that the exponent result has the expected value.
	 *
	 * @param exponent1Value The exponent1 value.
	 * @param exponent2Value The exponent2 value.
	 * @param expectedResult The expected value of the result of adding those two exponents.
	 */
	private void addExponentsAndAssert(final BigInteger exponent1Value, final BigInteger exponent2Value, final BigInteger expectedResult) {

		ZqElement exponent1 = ZqElement.create(exponent1Value, smallQGroup);
		ZqElement exponent2 = ZqElement.create(exponent2Value, smallQGroup);

		exponent1 = exponent1.add(exponent2);

		assertEquals(expectedResult, exponent1.getValue(), "The operation result is invalid");
	}

	/**
	 * Create the exponents with the given values, and subtract them: {@code (exponent1 - exponent2)}. Then assert that the exponent result has the
	 * expected value
	 *
	 * @param exponent1Value The exponent1 value.
	 * @param exponent2Value The exponent2 value.
	 * @param expectedResult The expected value of the result of subtracting those two exponents: {@code (exponent1 - exponent2)}.
	 */
	private void subtractExponentsAndAssert(final BigInteger exponent1Value, final BigInteger exponent2Value, final BigInteger expectedResult) {

		ZqElement exponent1 = ZqElement.create(exponent1Value, smallQGroup);
		ZqElement exponent2 = ZqElement.create(exponent2Value, smallQGroup);

		exponent1 = exponent1.subtract(exponent2);

		assertEquals(expectedResult, exponent1.getValue(), "The operation result is invalid");
	}

	/**
	 * Create the exponents with the given values, and multiplies them: {@code (exponent1 * exponent2)}. Then assert that the exponent result has the
	 * expected value
	 *
	 * @param exponent1Value The exponent1 value.
	 * @param exponent2Value The exponent2 value.
	 * @param expectedResult The expected value of the result of multiplying those two exponents: {@code (exponent1 * exponent2)}.
	 */
	private void multiplyExponentsAndAssert(final BigInteger exponent1Value, final BigInteger exponent2Value, final BigInteger expectedResult) {
		ZqElement exponent1 = ZqElement.create(exponent1Value, smallQGroup);
		ZqElement exponent2 = ZqElement.create(exponent2Value, smallQGroup);

		exponent1 = exponent1.multiply(exponent2);

		assertEquals(expectedResult, exponent1.getValue(), "The operation result is invalid");
	}

	/**
	 * Create the {@link ZqElement} with the given {@code elementValue}, and exponentiate it to {@code exponent}. Then assert that the result is the
	 * expected value.
	 *
	 * @param elementValue   The base value.
	 * @param exponent       The exponent.
	 * @param expectedResult The expected value of the result of exponentiating the base with the exponent: {@code (element ^ exponent)}
	 */
	private void exponentiateAndAssert(final BigInteger elementValue, final BigInteger exponent, final BigInteger expectedResult) {
		final ZqElement element = ZqElement.create(elementValue, smallQGroup);

		final ZqElement result = element.exponentiate(exponent);

		assertEquals(expectedResult, result.getValue(), "The exponentiate result is invalid");
	}

	/**
	 * Creates the exponent with the {@code exponentValue}, and negate it. Asserts that the negated exponent has the {@code expectedValue}.
	 *
	 * @param exponentValue The value for the exponent.
	 * @param expectedValue The expected value for the negated exponent.
	 */
	private void negateExponentAndAssert(final BigInteger exponentValue, final BigInteger expectedValue) {
		ZqElement exponent = ZqElement.create(exponentValue, smallQGroup);
		ZqElement negated = exponent.negate();

		assertEquals(expectedValue, negated.getValue(), "The negated exponent has not the expected value");
	}
}
