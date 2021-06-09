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

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Objects;

import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;

/**
 * Represents the statement for the shuffle argument, consisting of a ciphertexts vector <b>C</b> and a shuffled and re-encrypted ciphertexts vector
 * <b>C'</b>.
 */
@SuppressWarnings({"java:S100", "java:S116", "java:S117"})
class ShuffleStatement {

	private final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> C;
	private final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> C_prime;

	private final int N;
	private final GqGroup group;

	/**
	 * Instantiates a shuffle statement. The vector of input ciphertexts and the vector of shuffled, re-encrypted ciphertexts must comply with the
	 * following:
	 *
	 * <ul>
	 *     <li>be non null and non empty</li>
	 *     <li>both vectors must have the same size</li>
	 *     <li>ciphertexts and shuffled ciphertexts must have the same size</li>
	 *     <li>both vectors must be part of the same group</li>
	 * </ul>
	 *
	 * @param C         <b>C</b>, the ciphertexts as a {@link GroupVector}. All ciphertexts must have the same size.
	 * @param C_prime <b>C'</b>, the shuffled and re-encrypted ciphertexts as a {@link GroupVector}. All shuffled ciphertexts must
	 *                            have the same size.
	 */
	ShuffleStatement(final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> C,
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> C_prime) {

		checkNotNull(C);
		checkNotNull(C_prime);

		// Dimensions checking.
		checkArgument(!C.isEmpty(), "The ciphertexts vector cannot be empty.");
		checkArgument(!C_prime.isEmpty(), "The shuffled ciphertexts vector cannot be empty.");
		checkArgument(C.size() == C_prime.size(), "The ciphertexts and shuffled ciphertexts vectors must have the same size.");
		checkArgument(C.getElementSize() == C_prime.getElementSize(),
				"The ciphertexts and shuffled ciphertexts must have the same size.");

		// Cross group checking.
		checkArgument(C.getGroup().equals(C_prime.getGroup()),
				"The ciphertexts and shuffled ciphertexts must be part of the same group.");

		this.C = C;
		this.C_prime = C_prime;
		this.N = C.size();
		this.group = C.getGroup();
	}

	GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> get_C() {
		return C;
	}

	GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> get_C_prime() {
		return C_prime;
	}

	int get_N() {
		return N;
	}

	GqGroup getGroup() {
		return group;
	}

	@Override
	public boolean equals(final Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		final ShuffleStatement that = (ShuffleStatement) o;
		return C.equals(that.C) && C_prime.equals(that.C_prime);
	}

	@Override
	public int hashCode() {
		return Objects.hash(C, C_prime);
	}
}
