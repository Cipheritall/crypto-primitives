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
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.VerificationResult;

/**
 * Provides methods for generating zero-knowledge proofs.
 */
public interface ZeroKnowledgeProof {

	/**
	 * Decrypts a vector of ciphertexts in a verifiable way.
	 *
	 * @param ciphertexts          C, a vector of ciphertexts to be decrypted. Non null and non empty.
	 * @param keyPair              (pk, sk), a pair of a public key and a secret key. Non null.
	 * @param auxiliaryInformation i<sub>Aux</sub>, a list of context specific strings. Non null. Can be empty.
	 * @return a {@link VerifiableDecryptions} containing the partially decrypted ciphertexts and a decryption proof for each message
	 * @throws NullPointerException     if {@code ciphertexts} or {@code keyPair} is null
	 * @throws IllegalArgumentException if
	 *                                  <ul>
	 *                                  	 <li>the ciphertexts and the keys in the key pair do not have the same group</li>
	 *                                  	 <li>the ciphertexts are longer than the length of the key pair</li>
	 *                                  </ul>
	 */
	VerifiableDecryptions genVerifiableDecryptions(final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts, final ElGamalMultiRecipientKeyPair keyPair,
			final List<String> auxiliaryInformation);

	/**
	 * Verifies the validity of the given {@link DecryptionProof}s.
	 *
	 * @param ciphertexts          C, the ciphertexts. Must be non null.
	 * @param publicKey            pk, the public key that was used to generate the proofs. Must be non null.
	 * @param verifiableDecryptions (C', pi<sub>dec</sub>), the partially decrypted ciphertexts with their corresponding proofs. Must be non null.
	 * @param auxiliaryInformation i<sub>aux</sub>, auxiliary information that was used during proof generation. Must be non null and not contain null
	 *                             elements.
	 * @return the result of the verification.
	 */
	VerificationResult verifyDecryptions(final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts, final ElGamalMultiRecipientPublicKey publicKey,
			final VerifiableDecryptions verifiableDecryptions, final List<String> auxiliaryInformation);

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

	/**
	 * Verifies the validity of a given {@link ExponentiationProof}.
	 *
	 * @param bases                g, the bases that were used to generate the proof. Must be non null.
	 * @param exponentiations      y, the exponentiations that were used to generate the proof. Must be non null.
	 * @param proof                (e, z), the proof to be verified
	 * @param auxiliaryInformation i<sub>aux</sub>, auxiliary information that was used during proof generation. Must be non null and not contain
	 *                             nulls.
	 * @return {@code true} if the exponentiation proof is valid, {@code false} otherwise.
	 * @throws NullPointerException     if any of the bases, exponentiations, or proof is null
	 * @throws IllegalArgumentException if
	 *                                  <ul>
	 *                                      <li>the auxiliary information contains null elements</li>
	 *                                      <li>the bases are empty</li>
	 *                                      <li>the exponentations do not have the same size as the bases</li>
	 *                                      <li>the bases and the exponentiations do not have the same group</li>
	 *                                      <li>the exponentiation proof does not have the same group order as the bases and the exponentiations</li>
	 *                                      <li>the group order q's bit length is smaller than the hash service's hash length</li>
	 *                                  </ul>
	 */
	boolean verifyExponentiation(final GroupVector<GqElement, GqGroup> bases, final GroupVector<GqElement, GqGroup> exponentiations,
			final ExponentiationProof proof, final List<String> auxiliaryInformation);
}
