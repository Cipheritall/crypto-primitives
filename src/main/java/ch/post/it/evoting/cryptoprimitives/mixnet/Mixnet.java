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

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;

public interface Mixnet {

	/**
	 * Shuffles (including re-encryption) and provides a Bayer-Groth argument of the shuffle.
	 *<p>
	 * Additionally to the individual arguments preconditions the following cross-argument preconditions must be met:
	 * <ul>
	 *     <li>All ciphertexts and the public key must be from the same group</li>
	 *     <li>The size of the ciphertexts must be smaller or equal to the public key size and greater than 0</li>
	 * </ul>
	 *
	 * @param ciphertexts C,	the collection of {@link ElGamalMultiRecipientCiphertext} to be shuffled. Must not be null and must not contain
	 *                       nulls. All elements must be from the same group and of the same size. The number of elements must be in the range
	 *                       [2, q - 2) where q is the order of the group.
	 * @param publicKey  pk, the {@link ElGamalMultiRecipientPublicKey} to be used for re-encrypting. Not null.
	 * @return the Bayer-Groth shuffle proof and the shuffled ciphertexts as a {@link VerifiableShuffle}
	 */
	VerifiableShuffle genVerifiableShuffle(final List<ElGamalMultiRecipientCiphertext> ciphertexts, final ElGamalMultiRecipientPublicKey publicKey);
}
