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
package ch.post.it.evoting.cryptoprimitives.elgamal;

import static com.google.common.base.Preconditions.checkArgument;

import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.Hashable;
import ch.post.it.evoting.cryptoprimitives.HashableList;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;

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
public final class ElGamalMultiRecipientPublicKey implements ElGamalMultiRecipientObject<GqElement, GqGroup>, HashableList {

	private final GroupVector<GqElement, GqGroup> publicKeyElements;

	/**
	 * Creates an {@link ElGamalMultiRecipientPublicKey} object.
	 *
	 * @param keyElements <p>the list of public key Gq group publicKeyElements, which must satisfy the conditions of a {@link GroupVector} and
	 *                    the following:
	 *                    <li>not be empty</li>
	 *                    <li>no element must be equal to 1</li>
	 *                    <li>no element must be equal to the generator of the group they belong to</li></p>
	 */
	public ElGamalMultiRecipientPublicKey(final List<GqElement> keyElements) {
		this.publicKeyElements = GroupVector.from(keyElements);
		checkArgument(!publicKeyElements.isEmpty(), "An ElGamal public key must not be empty.");
		checkArgument(keyElements.stream().map(GqElement::getValue).allMatch(value -> value.compareTo(BigInteger.ONE) != 0),
				"An ElGamal public key cannot contain a 1 valued element.");
		checkArgument(keyElements.stream().allMatch(element -> element.getValue().compareTo(element.getGroup().getGenerator().getValue()) != 0),
				"An ElGamal public key cannot contain an element value equal to the group generator.");
	}

	/**
	 * This method implements the specification algorithm CompressPublicKey algorithm. It compresses the public key to the requested length.
	 * <p>
	 * The {@code length} must comply with the following:
	 * <ul>
	 * 	<li>the length must be strictly positive.</li>
	 * 	<li>the length must be at most the public key size.</li>
	 * </ul>
	 *
	 * @param length l, the requested length for key compression.
	 * @return An output vector with the first {@code length}-1 elements of the public key followed by the compressed computed element.
	 */
	public List<GqElement> compress(final int length) {

		final int k = this.size();

		checkArgument(0 < length, "The requested length for key compression must be strictly positive.");
		checkArgument(length <= k, "The requested length for key compression must be at most the public key size.");

		final GqElement compressedKeyElement = this.stream()
				.skip(length - 1L)
				.reduce(this.getGroup().getIdentity(), GqElement::multiply);

		final List<GqElement> keyElements = new LinkedList<>(this.publicKeyElements.subList(0, length - 1));

		keyElements.add(compressedKeyElement);

		return keyElements;
	}

	@Override
	public GqGroup getGroup() {
		//An ElGamal public key is not empty
		return this.publicKeyElements.getGroup();
	}

	@Override
	public int size() {
		return this.publicKeyElements.size();
	}

	@Override
	public GqElement get(int i) {
		return this.publicKeyElements.get(i);
	}

	@Override
	public Stream<GqElement> stream() {
		return this.publicKeyElements.stream();
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		ElGamalMultiRecipientPublicKey publicKey = (ElGamalMultiRecipientPublicKey) o;
		return publicKeyElements.equals(publicKey.publicKeyElements);
	}

	@Override
	public int hashCode() {
		return Objects.hash(publicKeyElements);
	}

	@Override
	public ImmutableList<? extends Hashable> toHashableForm() {
		return this.publicKeyElements.toHashableForm();
	}
}
