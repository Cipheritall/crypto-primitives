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

import static ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext.getCiphertext;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientMessage;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

/**
 * Re-encrypting shuffle service.
 */
@SuppressWarnings("java:S117")
public class ShuffleService {

	private final RandomService randomService;
	private final PermutationService permutationService;

	ShuffleService(final RandomService randomService, final PermutationService permutationService) {
		this.randomService = randomService;
		this.permutationService = permutationService;
	}

	/**
	 * Shuffles and re-encrypts a list of ciphertext with the given key.
	 *
	 * @param ciphertexts the ciphertexts to re-encrypt and shuffle. Must be non null.
	 * @param publicKey   the public key with which to re-encrypt the ciphertexts. Must be non null.
	 * @return a {@link Shuffle} with the result of the re-encrypting shuffle.
	 */
	Shuffle genShuffle(final List<ElGamalMultiRecipientCiphertext> ciphertexts, final ElGamalMultiRecipientPublicKey publicKey) {
		checkNotNull(ciphertexts);
		checkNotNull(publicKey);

		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> C = GroupVector.from(ciphertexts);
		final ElGamalMultiRecipientPublicKey pk = publicKey;
		final int N = C.size();
		final int l = C.getElementSize();
		final int k = publicKey.size();

		checkArgument(C.stream().allMatch(Objects::nonNull));
		if (C.isEmpty()) {
			return Shuffle.EMPTY;
		}
		checkArgument(C.allEqual(ElGamalMultiRecipientCiphertext::size), "All ciphertexts must have the same size.");

		//Verify combination of ciphertext and public key inputs
		checkArgument(0 < l);
		checkArgument(l <= k);
		checkArgument(C.getGroup().equals(publicKey.getGroup()));

		final GqGroup group = C.getGroup();
		final ZqGroup exponentGroup = ZqGroup.sameOrderAs(group);
		final BigInteger q = exponentGroup.getQ();

		//Generate shuffle
		final Permutation pi = this.permutationService.genPermutation(N);
		final ElGamalMultiRecipientMessage one = ElGamalMultiRecipientMessage.ones(group, l);

		final ImmutableList<ZqElement> r =
				Stream.generate(() -> randomService.genRandomInteger(q))
						.map(value -> ZqElement.create(value, exponentGroup))
						.limit(N)
						.collect(toImmutableList());

		final ImmutableList<ElGamalMultiRecipientCiphertext> C_prime =
				IntStream.range(0, N)
						.boxed()
						.flatMap(i -> Stream.of(i)
								.map(__ -> r.get(i))
								.map(r_i -> getCiphertext(one, r_i, pk))
								.map(e -> {
									final int pi_i = pi.get(i);
									final ElGamalMultiRecipientCiphertext C_pi_i = C.get(pi_i);
									return e.multiply(C_pi_i);
								})
						).collect(toImmutableList());

		return new Shuffle(C_prime, pi, r);
	}
}
