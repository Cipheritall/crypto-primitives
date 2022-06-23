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

import static ch.post.it.evoting.cryptoprimitives.math.GroupVector.toGroupVector;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableList;
import ch.post.it.evoting.cryptoprimitives.internal.elgamal.ElGamalMultiRecipientObject;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;

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

	private static final boolean ENABLE_PARALLEL_STREAMS = Boolean.parseBoolean(
			System.getProperty("enable.parallel.streams", Boolean.TRUE.toString()));

	private final GqElement gamma;
	private final GroupVector<GqElement, GqGroup> phis;
	private final GqGroup group;

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
	public ElGamalMultiRecipientCiphertext getCiphertextProduct(final ElGamalMultiRecipientCiphertext other) {
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

		IntStream indices = IntStream.range(0, l);
		if (ENABLE_PARALLEL_STREAMS) {
			indices = indices.parallel();
		}

		final GroupVector<GqElement, GqGroup> phi = indices
				.mapToObj(i -> phi_a.get(i).multiply(phi_b.get(i)))
				.collect(toGroupVector());

		return new ElGamalMultiRecipientCiphertext(gamma, phi);
	}

	/**
	 * Implements the specification GetCiphertextExponentiation algorithm. It exponentiates each element of the multi-recipient ciphertext by an
	 * exponent a.
	 * <p>
	 * The {@code exponent} parameter must comply with the following:
	 * <ul>
	 *     <li>the ciphertext to exponentiate and the exponent must belong to groups of same order.</li>
	 * </ul>
	 *
	 * @param exponent a, a {@code ZqElement}. Must be non null.
	 * @return a ciphertext whose gamma and phis values are exponentiated with {@code exponent}.
	 */
	public ElGamalMultiRecipientCiphertext getCiphertextExponentiation(final ZqElement exponent) {
		checkNotNull(exponent);
		checkArgument(this.group.hasSameOrderAs(exponent.getGroup()));
		final ZqElement a = exponent;

		final GqElement gamma = this.gamma.exponentiate(a);

		Stream<GqElement> elementStream;

		if (ENABLE_PARALLEL_STREAMS) {
			elementStream = this.phis.parallelStream();
		} else {
			elementStream = this.phis.stream();
		}
		GroupVector<GqElement, GqGroup> phi = elementStream
				.map(phi_i -> phi_i.exponentiate(a))
				.collect(toGroupVector());

		return new ElGamalMultiRecipientCiphertext(gamma, phi);
	}

	public GqElement getGamma() {
		return this.gamma;
	}

	public GroupVector<GqElement, GqGroup> getPhis() {
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
		final List<String> simplePhis = phis.stream().map(GqElement::getValue).map(BigInteger::toString).toList();
		return "ElGamalMultiRecipientCiphertext{" + "gamma=" + gamma + ", phis=" + simplePhis + '}';
	}

	@Override
	public List<? extends Hashable> toHashableForm() {
		return this.stream().toList();
	}
}

