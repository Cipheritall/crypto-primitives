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

package ch.post.it.evoting.cryptoprimitives.internal.elgamal;

import static ch.post.it.evoting.cryptoprimitives.internal.elgamal.ElGamalMultiRecipientMessages.getMessage;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.LinkedList;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientMessage;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPrivateKey;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

public class ElGamalMultiRecipientCiphertexts {

	private static final boolean ENABLE_PARALLEL_STREAMS = Boolean.parseBoolean(
			System.getProperty("enable.parallel.streams", Boolean.TRUE.toString()));

	private ElGamalMultiRecipientCiphertexts() {
		//Intentionally left blank
	}

	/**
	 * See {@link ch.post.it.evoting.cryptoprimitives.elgamal.ElGamal#neutralElement}
	 */
	public static ElGamalMultiRecipientCiphertext neutralElement(final int numPhi, final GqGroup group) {
		checkNotNull(group);
		checkArgument(numPhi > 0, "The neutral ciphertext must have at least one phi.");

		return ElGamalMultiRecipientCiphertext.create(group.getIdentity(), Stream.generate(group::getIdentity).limit(numPhi).toList());
	}

	/**
	 See {@link ElGamalService#getMessage}
	 **/
	public static ElGamalMultiRecipientCiphertext getCiphertext(final ElGamalMultiRecipientMessage message, final ZqElement exponent,
			final ElGamalMultiRecipientPublicKey publicKey) {

		checkNotNull(message);
		checkNotNull(exponent);
		checkNotNull(publicKey);
		checkArgument(message.getGroup().hasSameOrderAs(exponent.getGroup()), "Exponent and message groups must be of the same order.");
		checkArgument(message.getGroup().equals(publicKey.getGroup()), "Message and public key must belong to the same group. ");
		checkArgument(0 < message.size(), "The message must contain at least one element.");
		checkArgument(message.size() <= publicKey.size(), "There cannot be more message elements than public key elements.");

		final ElGamalMultiRecipientMessage m = message;
		final ZqElement r = exponent;
		final ElGamalMultiRecipientPublicKey pk = publicKey;

		final int l = m.size();
		final GqElement g = pk.getGroup().getGenerator();

		// Algorithm.
		final GqElement gamma = g.exponentiate(r);

		IntStream indices = IntStream.range(0, l);
		if (ENABLE_PARALLEL_STREAMS) {
			indices = indices.parallel();
		}
		final LinkedList<GqElement> phis = indices
				.parallel()
				.mapToObj(i -> pk.get(i).exponentiate(r).multiply(m.get(i)))
				.collect(Collectors.toCollection(LinkedList::new));

		return ElGamalMultiRecipientCiphertext.create(gamma, GroupVector.from(phis));
	}

	/**
	 * Takes a vector of ciphertexts, exponentiates them using the supplied exponents and returns the product of the exponentiated ciphertexts.
	 * <p>
	 * The {@code ciphertexts} and {@code exponents} parameters must comply with the following:
	 * <ul>
	 *     <li>the ciphertexts size must be equal to the exponents size.</li>
	 *     <li>the ciphertexts and the exponents must belong to groups of same order.</li>
	 * </ul>
	 *
	 * @param ciphertexts A List of {@code ElGamalMultiRecipientCiphertext}s, each element containing the same number of phis. Must be non null and
	 *                    not empty.
	 * @param exponents   A List of {@code ZqElement}s, of the same size as the ciphertexts list. Must be non null and not empty.
	 * @return the product of the exponentiated ciphertexts.
	 */
	public static ElGamalMultiRecipientCiphertext getCiphertextVectorExponentiation(
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts, final GroupVector<ZqElement, ZqGroup> exponents) {

		checkNotNull(ciphertexts);
		checkNotNull(exponents);
		checkArgument(!ciphertexts.isEmpty(), "Ciphertexts should not be empty");
		checkArgument(ciphertexts.size() == exponents.size(), "There should be a matching ciphertext for every exponent.");
		checkArgument(ciphertexts.getGroup().hasSameOrderAs(exponents.getGroup()), "Ciphertexts and exponents must be of the same group.");

		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> C = ciphertexts;
		final GroupVector<ZqElement, ZqGroup> a = exponents;
		final int l = C.getElementSize();
		final int n = a.size();

		final ElGamalMultiRecipientCiphertext neutralElement = neutralElement(l, C.getGroup());
		IntStream indices = IntStream.range(0, n);
		if (ENABLE_PARALLEL_STREAMS) {
			indices = indices.parallel();
		}
		return indices
				.mapToObj(i -> C.get(i).getCiphertextExponentiation(a.get(i)))
				.reduce(neutralElement, ElGamalMultiRecipientCiphertext::getCiphertextProduct);
	}

	/**
	 * Partially decrypts the ciphertext.
	 * <p>
	 * The {@code secretKey} parameter must comply with the following:
	 * <ul>
	 *     <li>the secret key and the ciphertext belong to groups of same order.</li>
	 *     <li>the secret key size is at least the size of the ciphertext size.</li>
	 * </ul>
	 *
	 * @param secretKey sk, the secret key to be used for decrypting. Must be not null.
	 * @return a new ciphertext with the partially decrypted plaintext message.
	 */
	public static ElGamalMultiRecipientCiphertext getPartialDecryption(final ElGamalMultiRecipientCiphertext ciphertext,
			final ElGamalMultiRecipientPrivateKey secretKey) {
		checkNotNull(secretKey);
		checkArgument(ciphertext.getGroup().hasSameOrderAs(secretKey.getGroup()), "Ciphertext and secret key must belong to groups of same order.");
		final int l = ciphertext.size();
		final int k = secretKey.size();
		checkArgument(0 < l, "The ciphertext must not be empty.");
		checkArgument(l <= k, "There cannot be more message elements than private key elements.");

		final ElGamalMultiRecipientCiphertext c = ciphertext;
		final ElGamalMultiRecipientPrivateKey sk = secretKey;

		final GqElement gamma = c.getGamma();
		final GroupVector<GqElement, GqGroup> m = getMessage(c, sk).getElements();

		return ElGamalMultiRecipientCiphertext.create(gamma, m);
	}
}
