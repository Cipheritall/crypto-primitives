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

import static ch.post.it.evoting.cryptoprimitives.math.GroupVector.toGroupVector;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableList;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

/**
 * Encapsulates an ElGamal multi recipient private key with N elements, each corresponding to a different recipient. The order of the elements must
 * match that of the elements of the associated public key.
 * <p>
 * Instances of this class are immutable.
 */
@SuppressWarnings("java:S117")
public final class ElGamalMultiRecipientPrivateKey implements ElGamalMultiRecipientObject<ZqElement, ZqGroup>, HashableList {

	private final GroupVector<ZqElement, ZqGroup> privateKeyElements;

	/**
	 * Creates an {@link ElGamalMultiRecipientPrivateKey} object.
	 *
	 * @param keyElements the list of private key Zq keyElements. Must respect the following:
	 *                    <ul>
	 *                    	<li>the list must be non-null.</li>
	 *                    	<li>the list must be non-empty.</li>
	 *                    	<li>the list must contain only non-null elements.</li>
	 *                    	<li>all elements from the list must be from the same mathematical group.</li>
	 *                    </ul>
	 */
	public ElGamalMultiRecipientPrivateKey(final List<ZqElement> keyElements) {
		this.privateKeyElements = GroupVector.from(keyElements);
		checkArgument(!privateKeyElements.isEmpty(), "An ElGamal private key cannot be empty.");
	}

	/**
	 * Derives the public key from the private key with the given {@code generator}.
	 *
	 * @param generator the group generator to be used for the public key derivation. Must be non-null and must belong to a group of the same order as
	 *                  the private key group.
	 * @return the derived public key with the given {@code generator}.
	 */
	ElGamalMultiRecipientPublicKey derivePublicKey(final GqElement generator) {
		checkNotNull(generator);
		checkArgument(generator.getGroup().hasSameOrderAs(this.getGroup()),
				"The private key and the generator must belong to groups of the same order.");

		final GroupVector<GqElement, GqGroup> publicKeyElements = this.stream().map(generator::exponentiate).collect(toGroupVector());

		return new ElGamalMultiRecipientPublicKey(publicKeyElements);
	}

	@Override
	public ZqGroup getGroup() {
		return this.privateKeyElements.getGroup();
	}

	@Override
	public int size() {
		return this.privateKeyElements.size();
	}

	/**
	 * @return the ith element.
	 */
	@Override
	public ZqElement get(final int i) {
		return this.privateKeyElements.get(i);
	}

	@Override
	public Stream<ZqElement> stream() {
		return this.privateKeyElements.stream();
	}

	@Override
	public boolean equals(final Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		final ElGamalMultiRecipientPrivateKey that = (ElGamalMultiRecipientPrivateKey) o;
		return this.privateKeyElements.equals(that.privateKeyElements);
	}

	@Override
	public int hashCode() {
		return Objects.hash(privateKeyElements);
	}

	@Override
	public ImmutableList<? extends Hashable> toHashableForm() {
		return privateKeyElements.toHashableForm();
	}
}
