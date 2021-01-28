/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GqGroupTestData;

@DisplayName("Instantiating a SingleValueProductWitness should...")
class SingleValueProductWitnessTest {

	private static final RandomService randomService = new RandomService();
	private static final int NUM_ELEMENTS = 5;

	private GqGroup gqGroup;
	private List<ZqElement> elements;
	private ZqElement randomness;

	@BeforeEach
	void setup() {
		gqGroup = GqGroupTestData.getGroup();
		ZqGroup zqGroup = ZqGroup.sameOrderAs(gqGroup);

		elements = Stream.generate(() -> randomService.genRandomExponent(zqGroup)).limit(NUM_ELEMENTS).collect(Collectors.toList());
		randomness = ZqElement.create(randomService.genRandomInteger(zqGroup.getQ()), zqGroup);
	}

	@Test
	@DisplayName("throw an Exception when passed null arguments")
	void constructSingleValueProductWitnessWithNullThrows() {
		List<ZqElement> elementsWithNull = new ArrayList<>(elements);
		elementsWithNull.add(null);
		assertAll(
				() -> assertThrows(NullPointerException.class, () -> new SingleValueProductWitness(null, randomness)),
				() -> assertThrows(NullPointerException.class, () -> new SingleValueProductWitness(elements, null)),
				() -> assertThrows(IllegalArgumentException.class, () -> new SingleValueProductWitness(elementsWithNull, randomness))
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
