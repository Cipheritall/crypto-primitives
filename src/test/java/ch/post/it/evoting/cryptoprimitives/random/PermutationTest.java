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
package ch.post.it.evoting.cryptoprimitives.random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.SecureRandom;
import java.util.TreeSet;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.math.RandomService;

class PermutationTest {

	private static final int MAX_PERMUTATION_TEST_SIZE = 1000;

	private static final SecureRandom random = new SecureRandom();
	private static final RandomService randomService = new RandomService();
	private static final PermutationService permutationService = new PermutationService(randomService);

	@Test
	void genPermutationThrowsForNonPositiveSize() {
		int size = -Math.abs(random.nextInt());
		assertThrows(IllegalArgumentException.class, () -> permutationService.genPermutation(size));
	}

	@RepeatedTest(10)
	void genPermutationContainsAllValuesInInputRange() {
		int size = random.nextInt(MAX_PERMUTATION_TEST_SIZE) + 1;
		Permutation permutation = permutationService.genPermutation(size);
		TreeSet<Integer> values = computePermutationValues(permutation);

		assertEquals(size, values.size());
		assertEquals(0, values.first());
		assertEquals(size - 1, values.last());
	}

	private TreeSet<Integer> computePermutationValues(Permutation permutation) {
		return IntStream.range(0, permutation.getSize()).map(permutation::get).boxed().collect(Collectors.toCollection(TreeSet::new));
	}

	@Test
	void getThrowsForNegativeValue() {
		int size = random.nextInt(MAX_PERMUTATION_TEST_SIZE) + 1;
		int value = -random.nextInt();
		Permutation permutation = permutationService.genPermutation(size);
		assertThrows(IllegalArgumentException.class, () -> permutation.get(value));
	}

	@Test
	void getThrowsForValueAboveSize() {
		int size = random.nextInt(MAX_PERMUTATION_TEST_SIZE) + 1;
		int value = random.nextInt(Integer.MAX_VALUE - size) + size;
		Permutation permutation = permutationService.genPermutation(size);
		assertThrows(IllegalArgumentException.class, () -> permutation.get(value));
	}

	@Test
	void getThrowsForValueOfSize() {
		int size = random.nextInt(MAX_PERMUTATION_TEST_SIZE) + 1;
		Permutation permutation = permutationService.genPermutation(size);
		assertThrows(IllegalArgumentException.class, () -> permutation.get(size));
	}

	@Test
	void getSizeReturnsSize() {
		int size = random.nextInt(MAX_PERMUTATION_TEST_SIZE) + 1;
		Permutation permutation = permutationService.genPermutation(size);
		assertEquals(size, permutation.getSize());
	}

	@Test
	void streamReturnsCorrectElements() {
		int size = random.nextInt(MAX_PERMUTATION_TEST_SIZE) + 1;
		Permutation permutation = permutationService.genPermutation(size);

		final int[] expectedArray = IntStream.range(0, permutation.getSize())
				.map(permutation::get)
				.toArray();

		assertArrayEquals(expectedArray, permutation.stream().toArray());
	}
}
