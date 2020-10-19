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
package ch.post.it.evoting.cryptoprimitives.zeroknowledgeproofs;

import java.util.List;

import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientKeyPair;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;

/**
 * Provides methods for generating zero-knowledge proofs.
 */
public interface ZeroKnowledgeProof {

	/**
	 * Decrypts a vector of ciphertexts in a verifiable way.
	 * <p>
	 * The input arguments must comply with the following:
	 * <ul>
	 *     <li>the ciphertexts and the keys in the key pair must have the same group</li>
	 *     <li>the ciphertexts must be smaller or equal to the length of the key pair</li>
	 * </ul>
	 *
	 * @param ciphertexts          C, a vector of ciphertexts to be decrypted. Non null and non empty.
	 * @param keyPair              (pk, sk), a pair of a public key and a secret key. Non null.
	 * @param auxiliaryInformation i<sub>Aux</sub>, a list of context specific strings. Non null. Can be empty.
	 * @return a {@link VerifiableDecryption} containing the partially decrypted ciphertexts and a decryption proof for each message
	 */
	VerifiableDecryption genVerifiableDecryptions(final List<ElGamalMultiRecipientCiphertext> ciphertexts, final ElGamalMultiRecipientKeyPair keyPair,
			final List<String> auxiliaryInformation);

	/**
	 * Generates a proof of validity for the provided exponentiations.
	 *
	 * @param bases                <b>g</b> ∈ G<sub>q</sub><sup>n</sup>. Not null and not empty.
	 * @param exponent             x ∈ Z<sub>q</sub>, a secret exponent. Not null.
	 * @param exponentiations      <b>y</b> ∈ G<sub>q</sub><sup>n</sup>. Not null and not empty.
	 * @param auxiliaryInformation i<sub>aux</sub>, auxiliary information to be used for the hash. Must be non null and not contain nulls. Can be
	 *                             empty.
	 * @return an exponentiation proof
	 * @throws NullPointerException     if any of the parameters are null.
	 * @throws IllegalArgumentException if
	 *                                  <ul>
	 *                                  	 <li>the bases and the exponentiations do not have the same group</li>
	 *                                  	 <li>the bases and the exponentiations do not have the same size</li>
	 *                                  	 <li>the exponent does not have the same group order as the exponentiations</li>
	 *                                  </ul>
	 */
	ExponentiationProof genExponentiationProof(final GroupVector<GqElement, GqGroup> bases, final ZqElement exponent,
			final GroupVector<GqElement, GqGroup> exponentiations, final List<String> auxiliaryInformation);
}
