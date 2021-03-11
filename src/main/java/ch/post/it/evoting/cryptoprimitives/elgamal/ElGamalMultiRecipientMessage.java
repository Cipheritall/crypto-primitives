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
import static java.util.stream.Collectors.collectingAndThen;
import static java.util.stream.Collectors.toList;

import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableList;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;

/**
 * Represents an ElGamal message containing mutliple elements.
 * <p>
 * This class is immutable.
 */
public class ElGamalMultiRecipientMessage implements ElGamalMultiRecipientObject<GqElement, GqGroup>, HashableList {

	private final GroupVector<GqElement, GqGroup> messageElements;

	public ElGamalMultiRecipientMessage(final List<GqElement> messageElements) {
		this.messageElements = GroupVector.from(messageElements);
		checkArgument(!this.messageElements.isEmpty(), "An ElGamal message must not be empty.");
	}

	/**
	 * Generates an {@link ElGamalMultiRecipientMessage} of ones.
	 *
	 * @param group the {@link GqGroup} of the message
	 * @param size  the number of ones to be contained in the message
	 * @return the message (1, ..., 1) with {@code size} elements
	 */
	public static ElGamalMultiRecipientMessage ones(final GqGroup group, final int size) {
		return constantMessage(GqElement.create(BigInteger.ONE, group), size);
	}

	/**
	 * Generates an {@link ElGamalMultiRecipientMessage} of constant value.
	 *
	 * @param constant the constant element of the message
	 * @param size     the size of the message
	 * @return the message of constants with {@code size} elements
	 */
	public static ElGamalMultiRecipientMessage constantMessage(final GqElement constant, final int size) {
		checkNotNull(constant);
		checkArgument(size > 0, "Cannot generate a message of constants of non positive length.");

		return Stream.generate(() -> constant)
				.limit(size)
				.collect(collectingAndThen(toList(), ElGamalMultiRecipientMessage::new));
	}

	/**
	 * Decrypts a ciphertext to obtain the plaintext message.
	 * <p>
	 * The {@code ciphertext} and {@code secretKey} parameters must comply with the following:
	 * <ul>
	 *     <li>the ciphertext and the secret key must belong to groups of same order.</li>
	 *     <li>the ciphertext size must be at most the secret key size.</li>
	 * </ul>
	 *
	 * @param ciphertext c,	the ciphertext to be decrypted. Must be non null.
	 * @param secretKey  sk, the secret key to be used for decrypting. Must be non null and not empty.
	 * @return the decrypted plaintext message
	 */
	static ElGamalMultiRecipientMessage getMessage(final ElGamalMultiRecipientCiphertext ciphertext,
			final ElGamalMultiRecipientPrivateKey secretKey) {

		checkNotNull(ciphertext);
		checkNotNull(secretKey);
		checkArgument(ciphertext.getGroup().hasSameOrderAs(secretKey.getGroup()), "Ciphertext and secret key must be of the same order");

		final int n = ciphertext.size();
		final int k = secretKey.size();
		// 0 < k is guaranteed by the checks performed during the construction of the ElGamalMultiRecipientCiphertext
		checkArgument(n <= k, "There cannot be more message elements than private key elements.");

		final GqElement gamma = ciphertext.getGamma();

		LinkedList<GqElement> messageElements = new LinkedList<>();
		// no key compression
		if (n == k) {
			messageElements = IntStream.range(0, n)
					.mapToObj(i -> ciphertext.get(i).multiply(gamma.exponentiate(secretKey.get(i).negate())))
					.collect(Collectors.toCollection(LinkedList::new));
		}
		// key compression
		else {
			if (n >= 2) {
				messageElements = IntStream.range(0, n - 1)
						.mapToObj(i -> ciphertext.get(i).multiply(gamma.exponentiate(secretKey.get(i).negate())))
						.collect(Collectors.toCollection(LinkedList::new));
			}
			ZqElement compressedKey = IntStream.range(n - 1, k)
					.mapToObj(secretKey::get).reduce(ZqElement::add)
					// Because of the precondition n <= k and the else condition n != k we are guaranteed to have at least two elements in the
					// stream, hence the reduce operation is guaranteed to succeed.
					.orElseThrow(() -> new RuntimeException("We should not reach this point."));
			messageElements.add(ciphertext.get(n - 1).multiply(gamma.exponentiate(compressedKey.negate())));
		}

		return new ElGamalMultiRecipientMessage(messageElements);
	}

	@Override
	public GqGroup getGroup() {
		//A ElGamalMultiRecipientMessage is never empty
		return this.messageElements.getGroup();
	}

	@Override
	public int size() {
		return this.messageElements.size();
	}

	@Override
	public GqElement get(int i) {
		return this.messageElements.get(i);
	}

	@Override
	public Stream<GqElement> stream() {
		return this.messageElements.stream();
	}

	@Override
	public boolean equals(final Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		final ElGamalMultiRecipientMessage that = (ElGamalMultiRecipientMessage) o;
		return messageElements.equals(that.messageElements);
	}

	@Override
	public int hashCode() {
		return Objects.hash(messageElements);
	}

	@Override
	public ImmutableList<? extends Hashable> toHashableForm() {
		return this.messageElements.toHashableForm();
	}
}
