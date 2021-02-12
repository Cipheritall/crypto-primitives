/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.Permutation;
import ch.post.it.evoting.cryptoprimitives.random.PermutationService;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GqGroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;

@DisplayName("A ShuffleWitness")
class ShuffleWitnessTest {

	private static final int PERMUTATION_SIZE = 10;
	private static final RandomService randomService = new RandomService();

	private static PermutationService permutationService;
	private static ZqGroupGenerator zqGroupGenerator;

	private Permutation permutation;
	private SameGroupVector<ZqElement, ZqGroup> randomness;

	@BeforeAll
	static void setUpAll() {
		final GqGroup gqGroup = GqGroupTestData.getGroup();
		final ZqGroup zqGroup = ZqGroup.sameOrderAs(gqGroup);
		zqGroupGenerator = new ZqGroupGenerator(zqGroup);
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
		final SameGroupVector<ZqElement, ZqGroup> emptyRandomness = SameGroupVector.of();

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ShuffleWitness(permutation, emptyRandomness));
		assertEquals("The randomness can not be empty.", exception.getMessage());
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
		final SameGroupVector<ZqElement, ZqGroup> otherRandomness = zqGroupGenerator.genRandomZqElementVector(PERMUTATION_SIZE + 1);
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