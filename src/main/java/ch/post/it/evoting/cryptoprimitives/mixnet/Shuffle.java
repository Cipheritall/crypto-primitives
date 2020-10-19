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

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;

/**
 * Represents the result of a re-encrypting shuffle operation. It contains the re-encrypted ciphertexts, the list of exponents used for re-encryption
 * and the permutation used for shuffling.
 * <p>
 * Instances of this class are immutable.
 */
public class Shuffle {
	static final Shuffle EMPTY = new Shuffle(ImmutableList.of(), Permutation.EMPTY, ImmutableList.of());

	private final ImmutableList<ElGamalMultiRecipientCiphertext> ciphertexts;
	private final Permutation permutation;
	private final ImmutableList<ZqElement> reEncryptionExponents;

	Shuffle(final ImmutableList<ElGamalMultiRecipientCiphertext> ciphertexts, final Permutation permutation,
			final ImmutableList<ZqElement> reEncryptionExponents) {
		this.ciphertexts = ciphertexts;
		this.permutation = permutation;
		this.reEncryptionExponents = reEncryptionExponents;
	}

	List<ElGamalMultiRecipientCiphertext> getCiphertexts() {
		return this.ciphertexts;
	}

	Permutation getPermutation() {
		return permutation;
	}

	ImmutableList<ZqElement> getReEncryptionExponents() {
		return reEncryptionExponents;
	}
}
