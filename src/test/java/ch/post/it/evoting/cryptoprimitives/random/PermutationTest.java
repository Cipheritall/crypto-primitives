/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.SecureRandom;
import java.util.TreeSet;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

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
}