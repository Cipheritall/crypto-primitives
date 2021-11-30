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

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableList;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

/**
 * An ElGamal multi-recipient ciphertext composed of a gamma and a list of phi (γ, 𝜙₀,..., 𝜙ₗ₋₁). The gamma is the left-hand side of a standard
 * ElGamal encryption. Each phi is the encryption of a different message, using a different public key element and the same randomness.
 * <p>
 * An ElGamal multi-recipient ciphertext cannot be empty. It contains always a γ and at least one 𝜙.
 *
 * <p>Instances of this class are immutable.
 */
@SuppressWarnings({ "java:S117", "java:S1117" })
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
		final ElGamalMultiRecipientCiphertext C_a = this;
		final ElGamalMultiRecipientCiphertext C_b = other;

		final GqElement gamma_a = C_a.gamma;
		final GqElement gamma_b = C_b.gamma;
		final GqElement gamma = gamma_a.multiply(gamma_b);

		final int l = C_a.size();
		final GroupVector<GqElement, GqGroup> phi_a = C_a.phis;
		final GroupVector<GqElement, GqGroup> phi_b = C_b.phis;
		final GroupVector<GqElement, GqGroup> phi = IntStream.range(0, l)
				.mapToObj(i -> phi_a.get(i).multiply(phi_b.get(i)))
				.collect(toGroupVector());

		return new ElGamalMultiRecipientCiphertext(gamma, phi);
	}

	/**
	 * Implements the specification GetCiphertextExponentiation algorithm. It exponentiates each element of the multi-recipient ciphertext by an exponent a.
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
		final ZqElement a = exponent;

		final GqElement gamma = this.gamma.exponentiate(a);
		final GroupVector<GqElement, GqGroup> phi = this.phis.stream()
				.map(phi_i -> phi_i.exponentiate(a))
				.collect(toGroupVector());

		return new ElGamalMultiRecipientCiphertext(gamma, phi);
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
		checkArgument(0 < message.size(), "The message must contain at least one element.");
		checkArgument(message.size() <= publicKey.size(), "There cannot be more message elements than public key elements.");

		final ElGamalMultiRecipientMessage m = message;
		final ZqElement r = exponent;
		final ElGamalMultiRecipientPublicKey pk = publicKey;

		final int l = m.size();
		final GqElement g = pk.getGroup().getGenerator();

		// Algorithm.
		final GqElement gamma = g.exponentiate(r);
		final ElGamalMultiRecipientPublicKey pk_prime = pk.compress(l);

		final LinkedList<GqElement> phis = IntStream.range(0, l)
				.mapToObj(i -> pk_prime.get(i).exponentiate(r).multiply(m.get(i)))
				.collect(Collectors.toCollection(LinkedList::new));

		return new ElGamalMultiRecipientCiphertext(gamma, GroupVector.from(phis));
	}

	/**
	 * Creates a {@code ElGamalMultiRecipientCiphertext} using the specified gamma and phi values.
	 *
	 * @param gamma The gamma (i.e. first) element of the ciphertext. {@code gamma} must be a valid GqElement different from the GqGroup generator.
	 * @param phis  The phi elements of the ciphertext, which must satisfy the following:
	 *              <ul>
	 *              <li>The list must be non-null.</li>
	 *              <li>The list must not be empty.</li>
	 *              <li>The list must not contain any null.</li>
	 *              <li>All elements must be from the same Gq group as gamma.</li>
	 *              </ul>
	 * @return A new ElGamalMultiRecipientCiphertext with the specified gamma and phis
	 */
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
	 * The neutral element for ciphertext multiplication is (γ, 𝜙₀,..., 𝜙ₗ₋₁) = (1, 1, ..., 1).
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

		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> C = ciphertexts;
		final GroupVector<ZqElement, ZqGroup> a = exponents;
		final int l = C.getElementSize();
		final int n = a.size();

		final ElGamalMultiRecipientCiphertext neutralElement = neutralElement(l, C.getGroup());
		return IntStream.range(0, n)
				.mapToObj(i -> C.get(i).exponentiate(a.get(i)))
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
		checkArgument(0 < l, "The ciphertext must not be empty.");
		checkArgument(l <= k, "There cannot be more message elements than private key elements.");

		final ElGamalMultiRecipientCiphertext c = this;
		final ElGamalMultiRecipientPrivateKey sk = secretKey;

		final GqElement gamma = c.getGamma();
		final GroupVector<GqElement, GqGroup> m = getMessage(c, sk).getElements();

		return new ElGamalMultiRecipientCiphertext(gamma, m);
	}

	public GqElement getGamma() {
		return this.gamma;
	}

	public GroupVector<GqElement, GqGroup> getPhi() {
		return this.phis;
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

