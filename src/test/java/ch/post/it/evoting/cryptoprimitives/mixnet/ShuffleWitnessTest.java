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
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.Permutation;
import ch.post.it.evoting.cryptoprimitives.random.PermutationService;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;

@DisplayName("A ShuffleWitness")
class ShuffleWitnessTest extends TestGroupSetup {

	private static final int PERMUTATION_SIZE = 10;
	private static final RandomService randomService = new RandomService();

	private static PermutationService permutationService;

	private Permutation permutation;
	private GroupVector<ZqElement, ZqGroup> randomness;

	@BeforeAll
	static void setUpAll() {
		permutationService = new PermutationService(randomService);
	}

	@BeforeEach
	void setUp() {
		permutation = permutationService.genPermutation(PERMUTATION_SIZE);
		randomness = zqGroupGenerator.genRandomZqElementVector(PERMUTATION_SIZE);
	}

	@Test
	@DisplayName("with valid parameter gives expected witness")
	void construct() {
		final ShuffleWitness shuffleWitness = new ShuffleWitness(permutation, randomness);

		assertEquals(shuffleWitness.getPermutation().getSize(), shuffleWitness.getRandomness().size());
	}

	@Test
	@DisplayName("with any null parameter throws NullPointerException")
	void constructNullParams() {
		assertThrows(NullPointerException.class, () -> new ShuffleWitness(null, randomness));
		assertThrows(NullPointerException.class, () -> new ShuffleWitness(permutation, null));
	}

	@Test
	@DisplayName("with empty randomness throws IllegalArgumentException")
	void constructEmptyRandomness() {
		final GroupVector<ZqElement, ZqGroup> emptyRandomness = GroupVector.of();

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ShuffleWitness(permutation, emptyRandomness));
		assertEquals("The size of the permutation must be equal to the randomness vector size.", exception.getMessage());
	}

	@Test
	@DisplayName("with permutation and randomness of different size throws IllegalArgumentException")
	void constructPermutationRandomnessDiffSize() {
		final Permutation longerPermutation = permutationService.genPermutation(PERMUTATION_SIZE + 1);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ShuffleWitness(longerPermutation, randomness));
		assertEquals("The size of the permutation must be equal to the randomness vector size.", exception.getMessage());
	}

	@Test
	void testEquals() {
		final ShuffleWitness shuffleWitness1 = new ShuffleWitness(permutation, randomness);
		final ShuffleWitness shuffleWitness2 = new ShuffleWitness(permutation, randomness);

		final Permutation otherPermutation = permutationService.genPermutation(PERMUTATION_SIZE + 1);
		final GroupVector<ZqElement, ZqGroup> otherRandomness = zqGroupGenerator.genRandomZqElementVector(PERMUTATION_SIZE + 1);
		final ShuffleWitness shuffleWitness3 = new ShuffleWitness(otherPermutation, otherRandomness);

		assertEquals(shuffleWitness1, shuffleWitness1);
		assertEquals(shuffleWitness1, shuffleWitness2);
		assertNotEquals(shuffleWitness1, shuffleWitness3);
	}

	@Test
	void testHashCode() {
		final ShuffleWitness shuffleWitness1 = new ShuffleWitness(permutation, randomness);
		final ShuffleWitness shuffleWitness2 = new ShuffleWitness(permutation, randomness);

		assertEquals(shuffleWitness1, shuffleWitness2);
		assertEquals(shuffleWitness1.hashCode(), shuffleWitness1.hashCode());
		assertEquals(shuffleWitness1.hashCode(), shuffleWitness2.hashCode());
	}
}
