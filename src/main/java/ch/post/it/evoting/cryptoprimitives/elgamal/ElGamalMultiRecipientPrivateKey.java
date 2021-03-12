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
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

/**
 * Encapsulates an ElGamal multi recipient private key with N elements, each corresponding to a different recipient. The order of the elements must
 * match that of the elements of the associated public key.
 *
 * <p>Instances of this class are immutable. </p>
 */
public final class ElGamalMultiRecipientPrivateKey implements ElGamalMultiRecipientObject<ZqElement, ZqGroup> {

	private final SameGroupVector<ZqElement, ZqGroup> privateKeyElements;

	/**
	 * Creates an {@link ElGamalMultiRecipientPrivateKey} object.
	 *
	 * @param keyElements <p>the list of private key Zq keyElements, which must satisfy the conditions of a {@link SameGroupVector} and
	 *                    the following:
	 *                    <li>not be empty</li>
	 *                    <li>no element must be equal to 0</li>
	 *                    <li>no element must be equal to 1</li></p>
	 */
	public ElGamalMultiRecipientPrivateKey(final List<ZqElement> keyElements) {
		this.privateKeyElements = SameGroupVector.from(keyElements);
		checkArgument(!privateKeyElements.isEmpty(), "An ElGamal private key cannot be empty.");
		checkArgument(keyElements.stream().map(ZqElement::getValue).allMatch(value -> value.compareTo(BigInteger.ZERO) != 0),
				"An ElGamal private key cannot contain a 0 valued element.");
		checkArgument(keyElements.stream().map(ZqElement::getValue).allMatch(value -> value.compareTo(BigInteger.ONE) != 0),
				"An ElGamal private key cannot contain a 1 valued element.");
	}

	@Override
	public ZqGroup getGroup() {
		//A private key cannot be empty
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
	public ZqElement get(int i) {
		return this.privateKeyElements.get(i);
	}

	@Override
	public Stream<ZqElement> stream() {
		return this.privateKeyElements.stream();
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		ElGamalMultiRecipientPrivateKey that = (ElGamalMultiRecipientPrivateKey) o;
		return privateKeyElements.equals(that.privateKeyElements);
	}

	@Override
	public int hashCode() {
		return Objects.hash(privateKeyElements);
	}
}
