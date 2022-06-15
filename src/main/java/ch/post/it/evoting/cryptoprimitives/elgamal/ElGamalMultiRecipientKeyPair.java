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

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableList;
import ch.post.it.evoting.cryptoprimitives.internal.elgamal.ElGamalMultiRecipientKeyPairs;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.Random;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

/**
 * A multi-recipient ElGamal key pair consisting of a public and a private key with N elements.
 *
 * <p>Instances of this class are immutable. </p>
 */
public class ElGamalMultiRecipientKeyPair implements HashableList {

	private final ElGamalMultiRecipientPublicKey publicKey;
	private final ElGamalMultiRecipientPrivateKey privateKey;
	private final int numElements;

	private ElGamalMultiRecipientKeyPair(final ElGamalMultiRecipientPrivateKey privateKey, final ElGamalMultiRecipientPublicKey publicKey) {
		this.publicKey = publicKey;
		this.privateKey = privateKey;
		this.numElements = publicKey.size();
	}

	/**
	 * See {@link ElGamal#genKeyPair}
	 */
	public static ElGamalMultiRecipientKeyPair genKeyPair(final GqGroup group, final int numElements, final Random random) {
		checkNotNull(random);
		checkNotNull(group);
		checkArgument(numElements > 0, "Cannot generate a ElGamalMultiRecipient key pair with %s elements.", numElements);
		final int N = numElements;

		final GqElement g = group.getGenerator();
		final ZqGroup privateKeyGroup = ZqGroup.sameOrderAs(group);
		final BigInteger q = group.getQ();

		// Generate the private key as a list of random exponents
		final List<ZqElement> privateKeyElements =
				Stream.generate(() -> random.genRandomInteger(q))
						.map(value -> ZqElement.create(value, privateKeyGroup))
						.limit(N)
						.toList();

		final ElGamalMultiRecipientPrivateKey sk = new ElGamalMultiRecipientPrivateKey(privateKeyElements);
		final ElGamalMultiRecipientPublicKey pk = ElGamalMultiRecipientKeyPairs.derivePublicKey(sk, g);

		return new ElGamalMultiRecipientKeyPair(sk, pk);
	}

	/**
	 * See {@link ElGamal#from}
	 */
	public static ElGamalMultiRecipientKeyPair from(final ElGamalMultiRecipientPrivateKey privateKey, final GqElement generator) {
		checkNotNull(privateKey);
		checkNotNull(generator);
		checkArgument(generator.getGroup().hasSameOrderAs(privateKey.getGroup()),
				"The private key and the generator must belong to groups of the same order.");

		final ElGamalMultiRecipientPublicKey publicKey = privateKey.derivePublicKey(generator);

		return new ElGamalMultiRecipientKeyPair(privateKey, publicKey);
	}

	public ElGamalMultiRecipientPublicKey getPublicKey() {
		return publicKey;
	}

	public ElGamalMultiRecipientPrivateKey getPrivateKey() {
		return privateKey;
	}

	/**
	 * @return the number of elements contained in the key pair, i.e. the number of "recipients"
	 */
	public int size() {
		return this.numElements;
	}

	public GqGroup getGroup() {
		return publicKey.getGroup();
	}

	@Override
	public boolean equals(final Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		final ElGamalMultiRecipientKeyPair that = (ElGamalMultiRecipientKeyPair) o;
		return publicKey.equals(that.publicKey) && privateKey.equals(that.privateKey);
	}

	@Override
	public int hashCode() {
		return Objects.hash(publicKey, privateKey);
	}

	@Override
	public List<? extends Hashable> toHashableForm() {
		return List.of(publicKey, privateKey);
	}
}
