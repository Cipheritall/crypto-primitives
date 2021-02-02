package ch.post.it.evoting.cryptoprimitives.mixnet;

import static ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalTestDataGenerator.genRandomCiphertext;
import static ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalTestDataGenerator.genRandomCiphertexts;
import static ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalTestDataGenerator.genRandomPublicKey;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.Permutation;
import ch.post.it.evoting.cryptoprimitives.random.PermutationService;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GqGroupTestData;

class ShuffleServiceTest {

	static int NUM_ELEMENTS = 10;
	static int NUM_CIPHERTEXTS = 10;
	static RandomService randomService = new RandomService();
	static PermutationService permutationService = new PermutationService(randomService);
	static ShuffleService shuffleService = new ShuffleService(randomService, permutationService);

	private static GqGroup group;
	private static ElGamalMultiRecipientPublicKey randomPublicKey;
	private static List<ElGamalMultiRecipientCiphertext> randomCiphertexts;

	@BeforeAll
	static void setUp() {
		group = GqGroupTestData.getGroup();
		randomPublicKey = genRandomPublicKey(group, NUM_ELEMENTS);
		randomCiphertexts = Collections.singletonList(genRandomCiphertext(group, NUM_ELEMENTS));
	}

	@Test
	void testNullCiphertextsThrows() {
		assertThrows(NullPointerException.class, () -> shuffleService.genShuffle(null, randomPublicKey));
	}

	@Test
	void testNullPublicKeyThrows() {
		assertThrows(NullPointerException.class, () -> shuffleService.genShuffle(randomCiphertexts, null));
	}

	@Test
	void testNoCiphertextsReturnsEmptyShuffle() {
		List<ElGamalMultiRecipientCiphertext> ciphertexts = Collections.emptyList();
		assertEquals(Shuffle.EMPTY, shuffleService.genShuffle(ciphertexts, randomPublicKey));
	}

	@Test
	void testCiphertextLongerThanKeyThrows() {
		List<ElGamalMultiRecipientCiphertext> ciphertexts = Collections.singletonList(genRandomCiphertext(group, NUM_ELEMENTS + 1));
		assertThrows(IllegalArgumentException.class, () -> shuffleService.genShuffle(ciphertexts, randomPublicKey));
	}

	@Test
	void testCiphertextAndKeyFromDifferentGroupsThrows() {
		ElGamalMultiRecipientPublicKey otherGroupKey = genRandomPublicKey(GqGroupTestData.getDifferentGroup(group), NUM_ELEMENTS);
		assertThrows(IllegalArgumentException.class, () -> shuffleService.genShuffle(randomCiphertexts, otherGroupKey));
	}

	@Test
	void testShuffleCiphertextIsNotEqualToOriginal() {
		ElGamalMultiRecipientPublicKey publicKey = genRandomPublicKey(group, NUM_ELEMENTS);
		List<ElGamalMultiRecipientCiphertext> ciphertexts = genRandomCiphertexts(group, publicKey, NUM_ELEMENTS, NUM_CIPHERTEXTS);
		Shuffle shuffle = shuffleService.genShuffle(ciphertexts, publicKey);
		assertNotEquals(ciphertexts, shuffle.getCiphertexts());
	}

	@Test
	void testSpecificValues() {
		//Define group
		final BigInteger p = new BigInteger("23");
		final BigInteger q = new BigInteger("11");
		final BigInteger g = new BigInteger("2");
		GqGroup localGroup = new GqGroup(p, q, g);

		//Define N
		int numCiphertexts = 3;

		//Mock the permutation
		Permutation permutation = mock(Permutation.class);
		when(permutation.get(anyInt())).thenReturn(1, 2, 0);
		PermutationService permutationService = mock(PermutationService.class);
		when(permutationService.genPermutation(numCiphertexts)).thenReturn(permutation);

		//Mock random exponents
		RandomService randomService = mock(RandomService.class);
		ZqGroup exponentGroup = ZqGroup.sameOrderAs(localGroup);
		List<ZqElement> randomExponents = Stream.of(7, 5, 3)
				.map(r -> ZqElement.create(BigInteger.valueOf(r), exponentGroup))
				.collect(Collectors.toList());
		when(randomService.genRandomExponent(exponentGroup))
				.thenReturn(randomExponents.get(0), randomExponents.subList(1, randomExponents.size()).toArray(new ZqElement[] {}));

		//Create public key
		List<GqElement> pkElements =
				Stream.of(6, 4, 3).map(pki -> GqElement.create(BigInteger.valueOf(pki), localGroup)).collect(Collectors.toList());
		ElGamalMultiRecipientPublicKey publicKey = new ElGamalMultiRecipientPublicKey(pkElements);

		//Create ciphertexts
		Stream<List<Integer>> ciphertextValues = Stream.of(
				Arrays.asList(16, 18, 2, 2),
				Arrays.asList(13, 1, 3, 4),
				Arrays.asList(3, 3, 6, 6)
		);
		List<ElGamalMultiRecipientCiphertext> ciphertexts = valuesToCiphertext(ciphertextValues, localGroup);

		//Expected ciphertexts
		Stream<List<Integer>> expectedCiphertextValues = Stream.of(
				Arrays.asList(8, 3, 1, 8),
				Arrays.asList(4, 6, 3, 9),
				Arrays.asList(13, 1, 13, 8)
		);
		List<ElGamalMultiRecipientCiphertext> expectedCiphertexts = valuesToCiphertext(expectedCiphertextValues, localGroup);

		//Create shuffle
		ShuffleService shuffleService = new ShuffleService(randomService, permutationService);
		Shuffle shuffle = shuffleService.genShuffle(ciphertexts, publicKey);

		assertEquals(expectedCiphertexts, shuffle.getCiphertexts());
		assertEquals(permutation, shuffle.getPermutation());
		assertEquals(randomExponents, shuffle.getReEncryptionExponents());
	}

	//Convert a matrix of values to ciphertexts
	private List<ElGamalMultiRecipientCiphertext> valuesToCiphertext(Stream<List<Integer>> ciphertextValues, GqGroup group) {
		return ciphertextValues
				.map(values -> values.stream().map(BigInteger::valueOf).map(value -> GqElement.create(value, group)).collect(Collectors.toList()))
				.map(values -> ElGamalMultiRecipientCiphertext.create(values.get(0), values.subList(1, values.size())))
				.collect(Collectors.toList());
	}
}
