/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.elgamal;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;

/**
 * An ElGamal multi-recipient ciphertext composed of a gamma and a list of phi (γ, 𝜙₀,..., 𝜙ₙ₋₁). The gamma is the left-hand side of a standard
 * ElGamal encryption. Each phi is the encryption of a different message, using a different public key element and the same randomness.
 */
public final class ElGamalMultiRecipientCiphertext {

	private final GqElement gamma;
	private final SameGroupVector<GqElement, GqGroup> phis;
	private final GqGroup group;

	// Private constructor without input validation. Used only to internally construct new ciphertext whose elements have already been validated.
	private ElGamalMultiRecipientCiphertext(final GqElement gamma, final ImmutableList<GqElement> phis) {
		this.gamma = gamma;
		this.phis = new SameGroupVector<>(phis);
		this.group = gamma.getGroup();
	}

	/**
	 * Encrypt a message with the given public key and provided randomness.
	 *
	 * @param message   m, the plaintext message.
	 * @param exponent  r, a random exponent.
	 * @param publicKey pk, the public key to use to encrypt the message.
	 * @return A ciphertext containing the encrypted message.
	 */
	public static ElGamalMultiRecipientCiphertext getCiphertext(
			final ElGamalMultiRecipientMessage message,
			final ZqElement exponent,
			final ElGamalMultiRecipientPublicKey publicKey) {

		checkNotNull(message);
		checkNotNull(exponent);
		checkNotNull(publicKey);

		checkArgument(message.getGroup().getQ().equals(exponent.getGroup().getQ()), "Exponent and message groups must be of the same order.");
		checkArgument(message.getGroup().equals(publicKey.getGroup()), "Message and public key must belong to the same group. ");

		//The message is guaranteed to be non empty by the checks performed during the construction of the ElGamalMultiRecipientMessage
		checkArgument(message.size() <= publicKey.size(), "There can not be more message elements than public key elements.");

		int n = message.size();
		int k = publicKey.size();

		GqElement generator = publicKey.getGroup().getGenerator();
		GqElement gamma = generator.exponentiate(exponent);

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
			GqElement compressedKey =
					IntStream.range(n - 1, k).mapToObj(publicKey::get)
							.reduce(GqElement::multiply)
							// Because of the precondition n <= k and the else condition n != k we are guaranteed to have at least two elements in the
							// stream, hence the reduce operation is guaranteed to succeed.
							.orElseThrow(() -> new RuntimeException("We should not reach this point."));
			phis.add(compressedKey.exponentiate(exponent).multiply(message.get(n - 1)));
		}

		return new ElGamalMultiRecipientCiphertext(gamma, ImmutableList.copyOf(phis));
	}

	/**
	 * Creates a {@code ElGamalMultiRecipientCiphertext} using the specified gamma and phi values.
	 *
	 * @param gamma The gamma (i.e. first) element of the ciphertext. {@code gamma} must be a valid GqElement different from the GqGroup generator.
	 * @param phis  The phi elements of the ciphertext, which must satisfy the following:
	 *              <li>The list must be non-null.</li>
	 *              <li>The list must not be empty.</li>
	 *              <li>The list must not contain any null.</li>
	 *              <li>All elements must be from the same Gq group.</li>
	 */
	public static ElGamalMultiRecipientCiphertext create(final GqElement gamma, final List<GqElement> phis) {
		checkNotNull(gamma);

		SameGroupVector<GqElement, GqGroup> phisVector = new SameGroupVector<>(phis);
		checkArgument(gamma.getGroup().equals(phisVector.getGroup()), "Gamma and phis must belong to the same GqGroup.");

		return new ElGamalMultiRecipientCiphertext(gamma, ImmutableList.copyOf(phis));
	}

	/**
	 * Returns a {@code ElGamalMultiRecipientCiphertext} whose value is {@code (this * other)}.
	 *
	 * @param other The ciphertext to be multiplied by {@code this}. It must be non null and its gamma and phis must belong to the same group as the
	 *              gamma and phis of {@code this}.
	 * @return {@code this * other}.
	 */
	public ElGamalMultiRecipientCiphertext multiply(final ElGamalMultiRecipientCiphertext other) {
		checkNotNull(other);
		checkArgument(this.phis.size() == other.phis.size());
		checkArgument(this.group.equals(other.group));

		final GqElement resultGamma = this.gamma.multiply(other.gamma);

		final int n = this.phis.size();
		final ImmutableList<GqElement> resultPhis =
				IntStream.range(0, n)
						.mapToObj(i -> this.phis.get(i).multiply(other.phis.get(i)))
						.collect(ImmutableList.toImmutableList());

		return new ElGamalMultiRecipientCiphertext(resultGamma, resultPhis);
	}

	public final GqElement getGamma() {
		return this.gamma;
	}

	public final ImmutableList<GqElement> getPhis() {
		return this.phis.toList();
	}

	public GqGroup getGroup() {
		return this.group;
	}

	/**
	 * @return the number of phis in the ciphertext.
	 */
	public int size() {
		return phis.size();
	}

	@Override
	public boolean equals(Object o) {
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
		List<String> simplePhis = phis.toList().stream().map(GqElement::getValue).map(BigInteger::toString).collect(Collectors.toList());
		return "ElGamalMultiRecipientCiphertext{" + "gamma=" + gamma + ", phis=" + simplePhis + '}';
	}
}

