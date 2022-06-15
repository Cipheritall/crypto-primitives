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
package ch.post.it.evoting.cryptoprimitives.elgamal;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableList;
import ch.post.it.evoting.cryptoprimitives.internal.elgamal.ElGamalMultiRecipientObject;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;

/**
 * Encapsulates an ElGamal multi recipient public key with N elements, each corresponding to a different recipient. The order of the elements must
 * match that of the elements of the associated public key.
 *
 * <p>A recipient ElGamal public key is related to its associated ElGamal private key by the following
 * operation: <code>publicKey = g <sup>privateKey</sup> mod p</code>, where g is the generator and p the modulo of the Gq group to which the public
 * key belongs, and privateKey is a member of Zq (notice that Gq and Zq are of the same order). </p>
 *
 * <p>Instances of this class are immutable. </p>
 */
@SuppressWarnings("java:S117")
public final class ElGamalMultiRecipientPublicKey implements ElGamalMultiRecipientObject<GqElement, GqGroup>, HashableList {

	private final GroupVector<GqElement, GqGroup> publicKeyElements;

	/**
	 * Creates an {@link ElGamalMultiRecipientPublicKey} object.
	 *
	 * @param keyElements <p>the list of public key Gq group publicKeyElements. Must respect the following:
	 *                    <ul>
	 *                    	<li>the list must be non-null.</li>
	 *                    	<li>the list must be non-empty.</li>
	 *                    	<li>the list must contain only non-null elements.</li>
	 *                    	<li>all elements from the list must be from the same mathematical group.</li>
	 *                    </ul>
	 */
	public ElGamalMultiRecipientPublicKey(final List<GqElement> keyElements) {
		this.publicKeyElements = GroupVector.from(keyElements);
		checkArgument(!publicKeyElements.isEmpty(), "An ElGamal public key must not be empty.");
	}

	@Override
	public GqGroup getGroup() {
		return this.publicKeyElements.getGroup();
	}

	@Override
	public int size() {
		return this.publicKeyElements.size();
	}

	@Override
	public GqElement get(final int i) {
		return this.publicKeyElements.get(i);
	}

	@Override
	public Stream<GqElement> stream() {
		return this.publicKeyElements.stream();
	}

	/**
	 * @return a copy of the key elements as a list.
	 */
	public List<GqElement> getKeyElements() {
		return new ArrayList<>(publicKeyElements);
	}

	@Override
	public boolean equals(final Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		final ElGamalMultiRecipientPublicKey publicKey = (ElGamalMultiRecipientPublicKey) o;
		return this.publicKeyElements.equals(publicKey.publicKeyElements);
	}

	@Override
	public int hashCode() {
		return Objects.hash(publicKeyElements);
	}

	@Override
	public List<? extends Hashable> toHashableForm() {
		return this.publicKeyElements.toHashableForm();
	}

}
