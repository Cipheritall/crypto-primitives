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
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;

@DisplayName("Instantiating a SingleValueProductWitness should...")
class SingleValueProductWitnessTest {

	private static final RandomService randomService = new RandomService();
	private static final int NUM_ELEMENTS = 5;

	private ZqGroup zqGroup;
	private GroupVector<ZqElement, ZqGroup> elements;
	private ZqElement randomness;

	@BeforeEach
	void setup() {
		zqGroup = GroupTestData.getZqGroup();
		final ZqGroupGenerator zqGroupGenerator = new ZqGroupGenerator(zqGroup);

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
		final ZqGroup differentZqGroup = GroupTestData.getDifferentZqGroup(zqGroup);
		final ZqElement differentRandomness = differentZqGroup.getIdentity();
		assertThrows(IllegalArgumentException.class, () -> new SingleValueProductWitness(elements, differentRandomness));
	}

	@Test
	void testEquals() {
		final SingleValueProductWitness singleValueProdWitness1 = new SingleValueProductWitness(elements, randomness);
		final SingleValueProductWitness singleValueProdWitness2 = new SingleValueProductWitness(elements, randomness);
		final ZqElement otherRandomness = randomness.add(ZqElement.create(BigInteger.ONE, randomness.getGroup()));
		final SingleValueProductWitness singleValueProdWitness3 = new SingleValueProductWitness(elements, otherRandomness);

		assertEquals(singleValueProdWitness1, singleValueProdWitness1);
		assertEquals(singleValueProdWitness1, singleValueProdWitness2);
		assertNotEquals(singleValueProdWitness1, singleValueProdWitness3);
		assertNotEquals(null, singleValueProdWitness3);
	}
}
