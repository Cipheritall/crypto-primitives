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
package ch.post.it.evoting.cryptoprimitives.internal.mixnet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalUtils;
import ch.post.it.evoting.cryptoprimitives.internal.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.mixnet.Permutation;
import ch.post.it.evoting.cryptoprimitives.mixnet.Shuffle;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;

class ShuffleServiceTest {

	static int NUM_ELEMENTS = 10;
	static int NUM_CIPHERTEXTS = 10;
	static RandomService randomService = new RandomService();
	static PermutationService permutationService = new PermutationService(randomService);
	static ShuffleService shuffleService = new ShuffleService(randomService, permutationService);

	private static GqGroup group;
	private static ElGamalMultiRecipientPublicKey randomPublicKey;
	private static List<ElGamalMultiRecipientCiphertext> randomCiphertexts;
	private static ElGamalGenerator elGamalGenerator;

	@BeforeAll
	static void setUp() {
		group = GroupTestData.getGqGroup();
		elGamalGenerator = new ElGamalGenerator(group);
		randomPublicKey = elGamalGenerator.genRandomPublicKey(NUM_ELEMENTS);
		randomCiphertexts = Collections.singletonList(elGamalGenerator.genRandomCiphertext(NUM_ELEMENTS));
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
		final List<ElGamalMultiRecipientCiphertext> ciphertexts = Collections.emptyList();
		assertEquals(Shuffle.EMPTY, shuffleService.genShuffle(ciphertexts, randomPublicKey));
	}

	@Test
	void testCiphertextLongerThanKeyThrows() {
		final List<ElGamalMultiRecipientCiphertext> ciphertexts = Collections.singletonList(elGamalGenerator.genRandomCiphertext(NUM_ELEMENTS + 1));
		assertThrows(IllegalArgumentException.class, () -> shuffleService.genShuffle(ciphertexts, randomPublicKey));
	}

	@Test
	void testCiphertextAndKeyFromDifferentGroupsThrows() {
		final ElGamalGenerator otherGenerator = new ElGamalGenerator(GroupTestData.getDifferentGqGroup(group));
		final ElGamalMultiRecipientPublicKey otherGroupKey = otherGenerator.genRandomPublicKey(NUM_ELEMENTS);
		assertThrows(IllegalArgumentException.class, () -> shuffleService.genShuffle(randomCiphertexts, otherGroupKey));
	}

	@Test
	void testShuffleCiphertextIsNotEqualToOriginal() {
		final ElGamalMultiRecipientPublicKey publicKey = elGamalGenerator.genRandomPublicKey(NUM_ELEMENTS);
		final List<ElGamalMultiRecipientCiphertext> ciphertexts = elGamalGenerator.genRandomCiphertexts(publicKey, NUM_ELEMENTS, NUM_CIPHERTEXTS);
		final Shuffle shuffle = shuffleService.genShuffle(ciphertexts, publicKey);
		assertNotEquals(ciphertexts, shuffle.getCiphertexts());
	}

	@Test
	void immutableShuffle() {
		final List<ElGamalMultiRecipientCiphertext> ciphertexts = new ArrayList<>();
		final List<ZqElement> reEncryptionExponents = new ArrayList<>();

		final Shuffle shuffle = new Shuffle(ciphertexts, Permutation.EMPTY, reEncryptionExponents);
		ciphertexts.add(null);
		reEncryptionExponents.add(null);

		assertEquals(0, shuffle.getCiphertexts().size());
		assertEquals(0, shuffle.getReEncryptionExponents().size());
	}

	@Test
	void testSpecificValues() {
		//Define group
		final BigInteger p = BigInteger.valueOf(23);
		final BigInteger q = BigInteger.valueOf(11);
		final BigInteger g = BigInteger.valueOf(2);

		final GqGroup localGroup = new GqGroup(p, q, g);

		//Define N
		final int numCiphertexts = 3;

		//Mock the permutation
		final Permutation permutation = new Permutation(List.of(1, 2, 0));
		final PermutationService permutationService = mock(PermutationService.class);
		when(permutationService.genPermutation(numCiphertexts)).thenReturn(permutation);

		//Mock random exponents
		final RandomService randomService = mock(RandomService.class);
		final ZqGroup exponentGroup = ZqGroup.sameOrderAs(localGroup);
		final List<BigInteger> randomIntegers = Arrays.asList(BigInteger.valueOf(7), BigInteger.valueOf(5), BigInteger.valueOf(3));
		when(randomService.genRandomInteger(exponentGroup.getQ()))
				.thenReturn(randomIntegers.get(0), randomIntegers.subList(1, randomIntegers.size()).toArray(new BigInteger[] {}));

		//Create public key
		final List<GqElement> pkElements =
				Stream.of(6, 4, 3).map(pki -> GqElement.GqElementFactory.fromValue(BigInteger.valueOf(pki), localGroup)).collect(Collectors.toList());
		final ElGamalMultiRecipientPublicKey publicKey = new ElGamalMultiRecipientPublicKey(pkElements);

		//Create ciphertexts
		final Stream<List<Integer>> ciphertextValues = Stream.of(
				Arrays.asList(16, 18, 2, 2),
				Arrays.asList(13, 1, 3, 4),
				Arrays.asList(3, 3, 6, 6)
		);
		final List<ElGamalMultiRecipientCiphertext> ciphertexts = ElGamalUtils.valuesToCiphertext(ciphertextValues, localGroup);

		//Expected ciphertexts
		final Stream<List<Integer>> expectedCiphertextValues = Stream.of(
				Arrays.asList(8, 3, 1, 8),
				Arrays.asList(4, 6, 3, 9),
				Arrays.asList(13, 1, 13, 8)
		);
		final List<ElGamalMultiRecipientCiphertext> expectedCiphertexts = ElGamalUtils.valuesToCiphertext(expectedCiphertextValues, localGroup);

		//Create shuffle
		final ShuffleService shuffleService = new ShuffleService(randomService, permutationService);
		final Shuffle shuffle = shuffleService.genShuffle(ciphertexts, publicKey);

		assertEquals(expectedCiphertexts, shuffle.getCiphertexts());
		assertEquals(permutation, shuffle.getPermutation());
		assertEquals(randomIntegers.stream().map(r -> ZqElement.create(r, exponentGroup)).collect(Collectors.toList()),
				shuffle.getReEncryptionExponents());
	}
}
