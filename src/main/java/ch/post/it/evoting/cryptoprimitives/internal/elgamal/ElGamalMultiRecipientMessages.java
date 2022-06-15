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

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static java.util.stream.Collectors.collectingAndThen;
import static java.util.stream.Collectors.toList;

import java.math.BigInteger;
import java.util.LinkedList;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamal;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientMessage;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPrivateKey;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqElement.GqElementFactory;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;

public class ElGamalMultiRecipientMessages {

	private static final boolean ENABLE_PARALLEL_STREAMS = Boolean.parseBoolean(
			System.getProperty("enable.parallel.streams", Boolean.TRUE.toString()));

	private ElGamalMultiRecipientMessages() {
		//Intentionally left blank
	}

	/**
	 * See {@link ElGamal#ones}
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
	 * See {@link ElGamal#getMessage}
	 */
	public static ElGamalMultiRecipientMessage getMessage(final ElGamalMultiRecipientCiphertext ciphertext,
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
		if (ENABLE_PARALLEL_STREAMS) {
			indices = indices.parallel();
		}

		// Algorithm.
		final LinkedList<GqElement> messageElements = indices
				.mapToObj(i -> c.get(i).multiply(gamma.exponentiate(sk.get(i).negate())))
				.collect(Collectors.toCollection(LinkedList::new));

		return new ElGamalMultiRecipientMessage(messageElements);
	}
}
