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
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

/**
 * A multi-recipient ElGamal key pair consisting of a public and a private key with N elements.
 *
 * <p>Instances of this class are immutable. </p>
 */
public class ElGamalMultiRecipientKeyPair {

	private final ElGamalMultiRecipientPublicKey publicKey;
	private final ElGamalMultiRecipientPrivateKey privateKey;

	private ElGamalMultiRecipientKeyPair(final ElGamalMultiRecipientPrivateKey privateKey, final ElGamalMultiRecipientPublicKey publicKey) {
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}

	/**
	 * Generates a key pair in the specified group and with the specified number of elements.
	 *
	 * @param group         The {@link GqGroup} in which to generate the public keys. Not null.
	 * @param numElements,  N, the number of elements that each key (the public key and the private key) should be composed of. This value must be
	 *                      greater than 0.
	 * @param randomService a service providing randomness. Not null.
	 * @return the generated key pair.
	 */
	public static ElGamalMultiRecipientKeyPair genKeyPair(final GqGroup group, final int numElements, final RandomService randomService) {
		checkNotNull(randomService);
		checkNotNull(group);
		checkArgument(numElements > 0, "Cannot generate a ElGamalMultiRecipient key pair with %s elements.", numElements);

		final GqElement generator = group.getGenerator();
		final ZqGroup privateKeyGroup = ZqGroup.sameOrderAs(group);

		// Generate the private key as a list of random exponents
		final List<ZqElement> privateKeyElements =
				Stream.generate(() -> randomService.genRandomExponent(privateKeyGroup.getQ()))
						.limit(numElements)
						.collect(Collectors.toList());
		final ElGamalMultiRecipientPrivateKey privateKey = new ElGamalMultiRecipientPrivateKey(privateKeyElements);

		// Calculate the public key from the private key previously generated
		final List<GqElement> publicKeyElements = privateKeyElements.stream().map(generator::exponentiate).collect(Collectors.toList());
		final ElGamalMultiRecipientPublicKey publicKey = new ElGamalMultiRecipientPublicKey(publicKeyElements);

		return new ElGamalMultiRecipientKeyPair(privateKey, publicKey);
	}

	public ElGamalMultiRecipientPublicKey getPublicKey() {
		return publicKey;
	}

	public ElGamalMultiRecipientPrivateKey getPrivateKey() {
		return privateKey;
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
}
