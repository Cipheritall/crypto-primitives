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

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.List;
import java.util.Objects;

import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

/**
 * A verifiable decryption consisting of partially decrypted votes and a decryption proof for each partially decrypted vote.
 * <p>
 * Instances of this class are immutable.
 */
public class VerifiableDecryption {

	private final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts;
	private final GroupVector<DecryptionProof, ZqGroup> decryptionProofs;

	/**
	 * Instantiates a verifiable decryption from the given ciphertexts and decryption proofs.
	 * <p>
	 * The ciphertext and decryption proof vectors must comply with the following:
	 * <ul>
	 *     <li>have the same size</li>
	 *     <li>have the same group order</li>
	 * </ul>
	 *
	 * @param ciphertexts      a vector of partially decrypted ciphertexts. Must be non null.
	 * @param decryptionProofs a vector of proofs showing that the ciphertexts have been correctly decrypted. Must be non null.
	 */
	VerifiableDecryption(final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts,
			final GroupVector<DecryptionProof, ZqGroup> decryptionProofs) {
		checkNotNull(ciphertexts);
		checkNotNull(decryptionProofs);

		checkArgument(ciphertexts.size() == decryptionProofs.size(), "Each ciphertext must have exactly one decryption proof.");
		checkArgument(ciphertexts.getGroup().hasSameOrderAs(decryptionProofs.getGroup()),
				"The ciphertexts and decryption proofs must have groups of the same order.");

		this.ciphertexts = ciphertexts;
		this.decryptionProofs = decryptionProofs;
	}

	/**
	 * Returns the vector of ciphertexts associated to this verifiable decryption.
	 *
	 * @return an immutable list of {@link ElGamalMultiRecipientCiphertext}s
	 */
	public List<ElGamalMultiRecipientCiphertext> getCiphertexts() {
		return ciphertexts;
	}

	public List<DecryptionProof> getDecryptionProofs() {
		return decryptionProofs;
	}

	@Override
	public boolean equals(final Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		final VerifiableDecryption that = (VerifiableDecryption) o;
		return ciphertexts.equals(that.ciphertexts) && decryptionProofs.equals(that.decryptionProofs);
	}

	@Override
	public int hashCode() {
		return Objects.hash(ciphertexts, decryptionProofs);
	}
}
