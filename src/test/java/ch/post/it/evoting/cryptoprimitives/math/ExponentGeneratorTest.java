/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.math;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;

import ch.post.it.evoting.cryptoprimitives.random.RandomService;

class ExponentGeneratorTest {

	protected static RandomService randomService;
	private static ZqGroup smallGroup;
	private static ZqGroup largeGroup;

	@BeforeAll
	static void setUp() {
		randomService = new RandomService();

		BigInteger smallQ = BigInteger.valueOf(11);

		smallGroup = new ZqGroup(smallQ);

		BigInteger largeQ = new BigInteger(
				"12939396283335421049921068858211433233126495514407886569514225839757682339812461790679331327844644602883220990119774411868903477198509705601122060967876228374690884782515835193957431967788948058212827424653299092753997868946254919808472248036853722669403050712733694488968744510228391838051310280985322342007934383014040024686424936057526104107219736301677741547820020757730425737985559136062566612003974844221840214834045656737059437540810373459953783841199104522171826073664311433417300419939057142509409231555113555807016335721042732921970354542359833932880562757400121671030866342014401323096601105149589569705303");

		largeGroup = new ZqGroup(largeQ);
	}

	@Test
	void givenNullGroupAndCryptoSecureRandomWhenAttemptToCreateZqElementThenException() {
		assertThrows(NullPointerException.class, () -> ExponentGenerator.genRandomExponent(null, randomService));
	}

	@Test
	void givenNullRandomnessThenThrows() {
		assertThrows(NullPointerException.class, () -> ExponentGenerator.genRandomExponent(smallGroup, null));
	}

	@RepeatedTest(10)
	void testWhenRandomZqElementCreatedThenValueIsInRange() {
		ZqElement randomExponent = ExponentGenerator.genRandomExponent(smallGroup, randomService);

		assertTrue(randomExponent.getValue().compareTo(BigInteger.valueOf(2)) >= 0, "The random exponent should be equal or greater than 2");
		assertTrue(randomExponent.getValue().compareTo(BigInteger.ZERO) >= 0,
				"The random exponent should be equal or greater than zero"); //TODO exclude 0?
		assertTrue(randomExponent.getValue().compareTo(smallGroup.getQ()) < 0, "The random exponent should be less than q");
	}

	@Test
	void testGenRandomExponentUsesRandomness() {
		String errorMessage = "The random exponents should be different";

		RandomService spyRandomService = Mockito.spy(new RandomService());

		Mockito.doReturn(BigInteger.ZERO, BigInteger.ONE, BigInteger.valueOf(2)).when(spyRandomService).genRandomInteger(ArgumentMatchers.any());

		ZqElement exponent1 = ExponentGenerator.genRandomExponent(largeGroup, spyRandomService);
		ZqElement exponent2 = ExponentGenerator.genRandomExponent(largeGroup, spyRandomService);
		ZqElement exponent3 = ExponentGenerator.genRandomExponent(largeGroup, spyRandomService);

		Mockito.verify(spyRandomService, Mockito.times(3)).genRandomInteger(largeGroup.getQ().subtract(BigInteger.valueOf(2)));

		Assertions.assertNotEquals(exponent1.getValue(), exponent2.getValue(), errorMessage);
		Assertions.assertNotEquals(exponent1.getValue(), exponent3.getValue(), errorMessage);
		Assertions.assertNotEquals(exponent2.getValue(), exponent3.getValue(), errorMessage);
	}
}
