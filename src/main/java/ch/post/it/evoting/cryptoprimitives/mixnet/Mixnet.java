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

import java.security.NoSuchAlgorithmException;
import java.util.List;

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;

public interface Mixnet {

	/**
	 * Shuffles (including re-encryption) and provides a Bayer-Groth proof of the shuffle
	 *
	 * @param inputCiphertexts C,	the {@link ElGamalMultiRecipientCiphertext} to be shuffled
	 * @param mixingPublicKey  pk, the {@link ElGamalMultiRecipientPublicKey} to be used for re-encrypting
	 * @return the Bayer-Groth shuffle proof and the shuffled ciphertexts as {@link VerifiableShuffle}
	 */

	VerifiableShuffle genVerifiableShuffle(final List<ElGamalMultiRecipientCiphertext> inputCiphertexts,
			final ElGamalMultiRecipientPublicKey mixingPublicKey) throws NoSuchAlgorithmException;
}
