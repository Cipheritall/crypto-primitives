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

import java.util.List;
import java.util.Objects;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;

/**
 * A verifiable shuffle consisting of shuffled votes and an argument for the correctness of the shuffle.
 * <p>
 * Instances of this class are immutable.
 */
public class VerifiableShuffle {

	private final ImmutableList<ElGamalMultiRecipientCiphertext> shuffledCiphertextList;
	private final ShuffleArgument shuffleArgument;

	/**
	 * Instantiates a verifiable shuffle from the given shuffled ciphertexts and shuffle proof.
	 *
	 * @param shuffledCiphertextList a list of shuffled ciphertexts
	 * @param shuffleArgument 		 a shuffle argument proving the correctness of the shuffle
	 */
	public VerifiableShuffle(final List<ElGamalMultiRecipientCiphertext> shuffledCiphertextList, final ShuffleArgument shuffleArgument) {
		this.shuffledCiphertextList = ImmutableList.copyOf(shuffledCiphertextList);
		this.shuffleArgument = shuffleArgument;
	}

	public List<ElGamalMultiRecipientCiphertext> getShuffledCiphertexts() {
		return shuffledCiphertextList;
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
		return Objects.equals(shuffledCiphertextList, that.shuffledCiphertextList) && Objects
				.equals(shuffleArgument, that.shuffleArgument);
	}

	@Override
	public int hashCode() {
		return Objects.hash(shuffledCiphertextList, shuffleArgument);
	}
}
