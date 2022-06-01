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

import static ch.post.it.evoting.cryptoprimitives.math.GqElement.GqElementFactory;
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

import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableList;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;

/**
 * Represents an ElGamal message containing multiple elements.
 *
 * <p>Instances of this class are immutable.
 */
@SuppressWarnings({ "java:S117" })
public class ElGamalMultiRecipientMessage implements ElGamalMultiRecipientObject<GqElement, GqGroup>, HashableList {

	private static final boolean enableParallelStreams = Boolean.parseBoolean(
			System.getProperty("enable.parallel.streams", Boolean.TRUE.toString()));
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
		return constantMessage(GqElementFactory.fromValue(BigInteger.ONE, group), size);
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
		checkArgument(0 < ciphertext.size(), "A ciphertext must not be empty");
		checkArgument(ciphertext.size() <= secretKey.size(), "There cannot be more message elements than private key elements.");

		final ElGamalMultiRecipientCiphertext c = ciphertext;
		final ElGamalMultiRecipientPrivateKey sk = secretKey;

		final int l = c.size();
		final GqElement gamma = c.getGamma();

		IntStream indices = IntStream.range(0, l);
		if (enableParallelStreams) {
			indices = indices.parallel();
		}

		// Algorithm.
		final LinkedList<GqElement> messageElements = indices
				.mapToObj(i -> c.get(i).multiply(gamma.exponentiate(sk.get(i).negate())))
				.collect(Collectors.toCollection(LinkedList::new));

		return new ElGamalMultiRecipientMessage(messageElements);
	}

	@Override
	public GqGroup getGroup() {
		//A ElGamalMultiRecipientMessage is never empty
		return this.messageElements.getGroup();
	}

	/**
	 * Gets the elements composing this multi recipient message.
	 */
	public GroupVector<GqElement, GqGroup> getElements() {
		return messageElements;
	}

	@Override
	public int size() {
		return this.messageElements.size();
	}

	@Override
	public GqElement get(final int i) {
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
