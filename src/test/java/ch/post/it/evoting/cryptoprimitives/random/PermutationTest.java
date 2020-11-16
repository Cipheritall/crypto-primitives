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

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

class PermutationTest {

	private static final int MAX_PERMUTATION_TEST_SIZE = 1000;

	private static SecureRandom random;

	@BeforeAll
	static void setUp() {
		random = new SecureRandom();
	}

	@Test
	void genPermutationThrowsForNonPositiveSize() {
		int size = -Math.abs(random.nextInt());
		assertThrows(IllegalArgumentException.class, () -> Permutation.genPermutation(size));
	}

	@RepeatedTest(10)
	void genPermutationContainsAllValuesInInputRange() {
		int size = random.nextInt(MAX_PERMUTATION_TEST_SIZE);
		Permutation permutation = Permutation.genPermutation(size);
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
		int size = random.nextInt(MAX_PERMUTATION_TEST_SIZE);
		int value = -random.nextInt();
		Permutation permutation = Permutation.genPermutation(size);
		assertThrows(IllegalArgumentException.class, () -> permutation.get(value));
	}

	@Test
	void getThrowsForValueAboveSize() {
		int size = random.nextInt(MAX_PERMUTATION_TEST_SIZE);
		int value = random.nextInt(Integer.MAX_VALUE - size) + size;
		Permutation permutation = Permutation.genPermutation(size);
		assertThrows(IllegalArgumentException.class, () -> permutation.get(value));
	}

	@Test
	void getThrowsForValueOfSize() {
		int size = random.nextInt(MAX_PERMUTATION_TEST_SIZE);
		Permutation permutation = Permutation.genPermutation(size);
		assertThrows(IllegalArgumentException.class, () -> permutation.get(size));
	}

	@Test
	void getSizeReturnsSize() {
		int size = random.nextInt(MAX_PERMUTATION_TEST_SIZE);
		Permutation permutation = Permutation.genPermutation(size);
		assertEquals(size, permutation.getSize());
	}
}