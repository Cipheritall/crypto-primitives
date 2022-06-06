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

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.List;
import java.util.Objects;

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableList;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;

/**
 * A verifiable shuffle consisting of shuffled votes and an argument for the correctness of the shuffle.
 * <p>
 * Instances of this class are immutable.
 */
public class VerifiableShuffle implements HashableList {

	private final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> shuffledCiphertexts;
	private final ShuffleArgument shuffleArgument;

	/**
	 * Instantiates a verifiable shuffle from the given shuffled ciphertexts and shuffle proof.
	 * <p>
	 * The vector of shuffled ciphertexts and the shuffle argument must comply with the following:
	 * <ul>
	 *     <li>the size of the vector of shuffled ciphertexts must be equal to the size of the shuffle argument {@code N = n * m}</li>
	 *     <li>the size of each shuffled ciphertext element must be equal to the dimension {@code l} of the shuffle argument</li>
	 *     <li>have the same group</li>
	 * </ul>
	 *
	 * @param shuffledCiphertexts a vector of shuffled ciphertexts. Must be non-null.
	 * @param shuffleArgument     a shuffle argument proving the correctness of the shuffle. Must be non-null.
	 */
	public VerifiableShuffle(final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> shuffledCiphertexts,
			final ShuffleArgument shuffleArgument) {

		checkNotNull(shuffledCiphertexts);
		checkNotNull(shuffleArgument);

		checkArgument(shuffledCiphertexts.size() == shuffleArgument.get_n() * shuffleArgument.get_m(),
				"Shuffle ciphertext vector's size must be N = n * m.");
		checkArgument(shuffledCiphertexts.getElementSize() == shuffleArgument.get_l(),
				"Shuffled ciphertexts elements size must be dimension l of shuffle argument.");
		checkArgument(shuffledCiphertexts.getGroup().equals(shuffleArgument.getGroup()),
				"Shuffled ciphertext vector and shuffle argument must have the same group.");

		this.shuffledCiphertexts = shuffledCiphertexts;
		this.shuffleArgument = shuffleArgument;
	}

	public GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> getShuffledCiphertexts() {
		return shuffledCiphertexts;
	}

	public ShuffleArgument getShuffleArgument() {
		return shuffleArgument;
	}

	@Override
	public boolean equals(final Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		final VerifiableShuffle that = (VerifiableShuffle) o;
		return Objects.equals(shuffledCiphertexts, that.shuffledCiphertexts) && Objects
				.equals(shuffleArgument, that.shuffleArgument);
	}

	@Override
	public int hashCode() {
		return Objects.hash(shuffledCiphertexts, shuffleArgument);
	}

	@Override
	public List<? extends Hashable> toHashableForm() {
		return List.of(shuffledCiphertexts, shuffleArgument);
	}
}
