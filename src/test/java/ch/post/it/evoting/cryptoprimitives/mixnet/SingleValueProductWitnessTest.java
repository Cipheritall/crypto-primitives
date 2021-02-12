/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GqGroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;

@DisplayName("Instantiating a SingleValueProductWitness should...")
class SingleValueProductWitnessTest {

	private static final RandomService randomService = new RandomService();
	private static final int NUM_ELEMENTS = 5;

	private GqGroup gqGroup;
	private SameGroupVector<ZqElement, ZqGroup> elements;
	private ZqElement randomness;

	@BeforeEach
	void setup() {
		gqGroup = GqGroupTestData.getGroup();
		ZqGroup zqGroup = ZqGroup.sameOrderAs(gqGroup);
		ZqGroupGenerator zqGroupGenerator = new ZqGroupGenerator(zqGroup);

		elements = zqGroupGenerator.genRandomZqElementVector(NUM_ELEMENTS);
		randomness = ZqElement.create(randomService.genRandomInteger(zqGroup.getQ()), zqGroup);
	}

	@Test
	@DisplayName("throw an Exception when passed null arguments")
	void constructSingleValueProductWitnessWithNullThrows() {
		assertAll(
				() -> assertThrows(NullPointerException.class, () -> new SingleValueProductWitness(null, randomness)),
				() -> assertThrows(NullPointerException.class, () -> new SingleValueProductWitness(elements, null))
		);
	}

	@Test
	@DisplayName("throw an IllegalArgumentException when the elements and the randomness have different groups")
	void constructSingleValueProductWitnessWithElementsAndRandomnessDifferentGroupThrows() {
		GqGroup differentGqGroup = GqGroupTestData.getDifferentGroup(gqGroup);
		ZqGroup differentZqGroup = ZqGroup.sameOrderAs(differentGqGroup);
		ZqElement differentRandomness = differentZqGroup.getIdentity();
		assertThrows(IllegalArgumentException.class, () -> new SingleValueProductWitness(elements, differentRandomness));
	}

	@Test
	void testEquals() {
		SingleValueProductWitness singleValueProdWitness1 = new SingleValueProductWitness(elements, randomness);
		SingleValueProductWitness singleValueProdWitness2 = new SingleValueProductWitness(elements, randomness);
		ZqElement otherRandomness = randomness.add(ZqElement.create(BigInteger.ONE, randomness.getGroup()));
		SingleValueProductWitness singleValueProdWitness3 = new SingleValueProductWitness(elements, otherRandomness);

		assertEquals(singleValueProdWitness1, singleValueProdWitness1);
		assertEquals(singleValueProdWitness1, singleValueProdWitness2);
		assertNotEquals(singleValueProdWitness1, singleValueProdWitness3);
		assertNotEquals(null, singleValueProdWitness3);
	}
}
