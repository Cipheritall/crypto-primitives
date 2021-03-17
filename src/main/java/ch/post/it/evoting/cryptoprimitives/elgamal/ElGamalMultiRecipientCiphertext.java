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

import static ch.post.it.evoting.cryptoprimitives.GroupVector.toGroupVector;
import static ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientMessage.getMessage;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static java.util.stream.Collectors.toList;

import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.Hashable;
import ch.post.it.evoting.cryptoprimitives.HashableList;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

/**
 * An ElGamal multi-recipient ciphertext composed of a gamma and a list of phi (γ, 𝜙₀,..., 𝜙ₙ₋₁). The gamma is the left-hand side of a standard
 * ElGamal encryption. Each phi is the encryption of a different message, using a different public key element and the same randomness.
 */
public final class ElGamalMultiRecipientCiphertext implements ElGamalMultiRecipientObject<GqElement, GqGroup>, HashableList {

	private final GqElement gamma;
	private final GroupVector<GqElement, GqGroup> phis;
	private final GqGroup group;

	// Private constructor without input validation. Used only to internally construct new ciphertext whose elements have already been validated.
	private ElGamalMultiRecipientCiphertext(final GqElement gamma, final GroupVector<GqElement, GqGroup> phis) {
		this.gamma = gamma;
		this.phis = phis;
		this.group = gamma.getGroup();
	}

	/**
	 * Implements the specification GetCiphertextProduct algorithm. It multiplies two ciphertexts.
	 * <p>
	 * The {@code other} ciphertext parameter must comply with the following:
	 * <ul>
	 * 	<li>the other ciphertext size and the current ciphertext must be of same size.</li>
	 * 	<li>the phis and the gamma of the other ciphertext and the phis and the gamma of the current ciphertext must belong to the same group.</li>
	 * </ul>
	 *
	 * @param other c_b, the ciphertext to be multiplied by {@code this}. Must be non null.
	 * @return a ciphertext whose value is {@code this * other}.
	 */
	public ElGamalMultiRecipientCiphertext multiply(final ElGamalMultiRecipientCiphertext other) {
		checkNotNull(other);
		checkArgument(this.size() == other.size(), "Cannot multiply ciphertexts of different size.");
		checkArgument(this.group.equals(other.group), "Cannot multiply ciphertexts of different groups.");

		final GqElement resultGamma = this.gamma.multiply(other.gamma);

		final int n = this.size();
		final GroupVector<GqElement, GqGroup> resultPhis =
				IntStream.range(0, n)
						.mapToObj(i -> this.phis.get(i).multiply(other.phis.get(i)))
						.collect(toGroupVector());

		return new ElGamalMultiRecipientCiphertext(resultGamma, resultPhis);
	}

	/**
	 * Implements the specification GetCiphertextExponentiation algorithm. It exponentiates a multi-recipient ciphertext.
	 * <p>
	 * The {@code exponent} parameter must comply with the following:
	 * <ul>
	 *     <li>the ciphertext to exponentiate and the exponent must belong to groups of same order.</li>
	 * </ul>
	 *
	 * @param exponent a, a {@code ZqElement}. Must be non null.
	 * @return a ciphertext whose gamma and phis values are exponentiated with {@code exponent}.
	 */
	public ElGamalMultiRecipientCiphertext exponentiate(final ZqElement exponent) {
		checkNotNull(exponent);
		checkArgument(this.group.hasSameOrderAs(exponent.getGroup()));

		final GqElement exponentiatedGamma = this.gamma.exponentiate(exponent);
		final GroupVector<GqElement, GqGroup> exponentiatedPhis = this.phis.stream()
				.map(p -> p.exponentiate(exponent))
				.collect(toGroupVector());

		return new ElGamalMultiRecipientCiphertext(exponentiatedGamma, exponentiatedPhis);
	}

	/**
	 * Encrypts a message with the given public key and provided randomness.
	 * <p>
	 * The {@code message}, {@code exponent} and {@code publicKey} parameters must comply with the following:
	 * <ul>
	 *     <li>the message size must be at most the public key size.</li>
	 *     <li>the message and the public key groups must be the same.</li>
	 *     <li>the message and the exponent must belong to groups of same order.</li>
	 * </ul>
	 *
	 * @param message   m, the plaintext message. Must be non null and not empty.
	 * @param exponent  r, a random exponent. Must be non null.
	 * @param publicKey pk, the public key to use to encrypt the message. Must be non null.
	 * @return A ciphertext containing the encrypted message.
	 */
	public static ElGamalMultiRecipientCiphertext getCiphertext(final ElGamalMultiRecipientMessage message, final ZqElement exponent,
			final ElGamalMultiRecipientPublicKey publicKey) {

		checkNotNull(message);
		checkNotNull(exponent);
		checkNotNull(publicKey);
		checkArgument(message.getGroup().hasSameOrderAs(exponent.getGroup()), "Exponent and message groups must be of the same order.");
		checkArgument(message.getGroup().equals(publicKey.getGroup()), "Message and public key must belong to the same group. ");

		//The message is guaranteed to be non empty by the checks performed during the construction of the ElGamalMultiRecipientMessage
		checkArgument(message.size() <= publicKey.size(), "There cannot be more message elements than public key elements.");

		final int n = message.size();
		final int k = publicKey.size();

		final GqElement generator = publicKey.getGroup().getGenerator();
		final GqElement gamma = generator.exponentiate(exponent);

		LinkedList<GqElement> phis = new LinkedList<>();
		//No key compression
		if (n == k) {
			phis = IntStream.range(0, n)
					.mapToObj(i -> publicKey.get(i).exponentiate(exponent).multiply(message.get(i)))
					.collect(Collectors.toCollection(LinkedList::new));
		}
		// With key compression
		else {
			if (n >= 2) {
				phis = IntStream.range(0, n - 1)
						.mapToObj(i -> publicKey.get(i).exponentiate(exponent).multiply(message.get(i)))
						.collect(Collectors.toCollection(LinkedList::new));
			}
			final GqElement compressedKey =
					IntStream.range(n - 1, k).mapToObj(publicKey::get)
							.reduce(GqElement::multiply)
							// Because of the precondition n <= k and the else condition n != k we are guaranteed to have at least two elements in the
							// stream, hence the reduce operation is guaranteed to succeed.
							.orElseThrow(() -> new RuntimeException("We should not reach this point."));
			phis.add(compressedKey.exponentiate(exponent).multiply(message.get(n - 1)));
		}

		return new ElGamalMultiRecipientCiphertext(gamma, GroupVector.from(phis));
	}

	/**
	 * Creates a {@code ElGamalMultiRecipientCiphertext} using the specified gamma and phi values.
	 *
	 * @param gamma The gamma (i.e. first) element of the ciphertext. {@code gamma} must be a valid GqElement different from the GqGroup generator.
	 * @param phis  The phi elements of the ciphertext, which must satisfy the following:
	 *              <li>The list must be non-null.</li>
	 *              <li>The list must not be empty.</li>
	 *              <li>The list must not contain any null.</li>
	 *              <li>All elements must be from the same Gq group as gamma.</li>
	 */
	@VisibleForTesting
	public static ElGamalMultiRecipientCiphertext create(final GqElement gamma, final List<GqElement> phis) {
		checkNotNull(gamma);

		final GroupVector<GqElement, GqGroup> phisVector = GroupVector.from(phis);

		checkArgument(!phisVector.isEmpty(), "An ElGamalMultiRecipientCiphertext phis must be non empty.");
		checkArgument(gamma.getGroup().equals(phisVector.getGroup()), "Gamma and phis must belong to the same GqGroup.");

		return new ElGamalMultiRecipientCiphertext(gamma, phisVector);
	}

	/**
	 * Creates a neutral element for ciphertext multiplication.
	 * <p>
	 * The neutral element for ciphertext multiplication is (γ, 𝜙₀,..., 𝜙ₙ₋₁) = (1, 1, ..., 1).
	 *
	 * @param numPhi The number of phis in the neutral element.
	 * @param group  The {@link GqGroup} of the neutral element.
	 * @return A new {@link ElGamalMultiRecipientCiphertext} filled with ones.
	 */
	public static ElGamalMultiRecipientCiphertext neutralElement(final int numPhi, final GqGroup group) {
		checkNotNull(group);
		checkArgument(numPhi > 0, "The neutral ciphertext must have at least one phi.");

		return create(group.getIdentity(), Stream.generate(group::getIdentity).limit(numPhi).collect(toList()));
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

		final int numberOfPhiElements = ciphertexts.get(0).size();

		final ElGamalMultiRecipientCiphertext neutralElement = neutralElement(numberOfPhiElements, ciphertexts.getGroup());

		return IntStream
				.range(0, exponents.size())
				.mapToObj(i -> ciphertexts.get(i).exponentiate(exponents.get(i)))
				.reduce(neutralElement, ElGamalMultiRecipientCiphertext::multiply);
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
	public ElGamalMultiRecipientCiphertext getPartialDecryption(final ElGamalMultiRecipientPrivateKey secretKey) {

		checkNotNull(secretKey);
		checkArgument(this.getGroup().hasSameOrderAs(secretKey.getGroup()), "Ciphertext and secret key must belong to groups of same order.");

		final int l = this.size();
		final int k = secretKey.size();

		// 0 < l is ensured by the inputs validations when creating the ElGamalMultiRecipientCiphertext ciphertext.
		checkArgument(l <= k, "There cannot be more message elements than private key elements.");

		final ElGamalMultiRecipientMessage message = getMessage(this, secretKey);

		return new ElGamalMultiRecipientCiphertext(this.getGamma(), message.stream().collect(toGroupVector()));
	}

	public final GqElement getGamma() {
		return this.gamma;
	}

	/**
	 * @return the ith phi element.
	 */
	@Override
	public GqElement get(final int i) {
		return phis.get(i);
	}

	/**
	 * @return an ordered stream of gamma and phis.
	 */
	@Override
	public Stream<GqElement> stream() {
		return Stream.concat(Stream.of(this.gamma), this.phis.stream());
	}

	@Override
	public GqGroup getGroup() {
		return this.group;
	}

	/**
	 * @return the number of phis in the ciphertext.
	 */
	@Override
	public int size() {
		return phis.size();
	}

	@Override
	public boolean equals(final Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}

		final ElGamalMultiRecipientCiphertext that = (ElGamalMultiRecipientCiphertext) o;

		return gamma.equals(that.gamma) && phis.equals(that.phis);
	}

	@Override
	public int hashCode() {
		return Objects.hash(gamma, phis);
	}

	@Override
	public String toString() {
		final List<String> simplePhis = phis.stream().map(GqElement::getValue).map(BigInteger::toString).collect(Collectors.toList());
		return "ElGamalMultiRecipientCiphertext{" + "gamma=" + gamma + ", phis=" + simplePhis + '}';
	}

	@Override
	public ImmutableList<Hashable> toHashableForm() {
		return this.stream().collect(toImmutableList());
	}
}

