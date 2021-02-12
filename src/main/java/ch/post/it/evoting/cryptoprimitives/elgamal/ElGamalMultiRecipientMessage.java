/*
 * HEADER_LICENSE_OPEN_SOURCE
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

import ch.post.it.evoting.cryptoprimitives.Hashable;
import ch.post.it.evoting.cryptoprimitives.HashableList;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;

/**
 * Represents an ElGamal message containing mutliple elements.
 * <p>
 * This class is immutable.
 */
public class ElGamalMultiRecipientMessage implements ElGamalMultiRecipientObject<GqElement, GqGroup>, HashableList {

	private final SameGroupVector<GqElement, GqGroup> messageElements;

	public ElGamalMultiRecipientMessage(final List<GqElement> messageElements) {
		this.messageElements = new SameGroupVector<>(messageElements);
		checkArgument(!this.messageElements.isEmpty(), "An ElGamal message must not be empty.");
	}

	/**
	 * Generates an {@link ElGamalMultiRecipientMessage} of ones.
	 *
	 * @param size  the number of ones to be contained in the message
	 * @param group the {@link GqGroup} of the message
	 * @return the message (1, ..., 1) with {@code size} elements
	 */
	public static ElGamalMultiRecipientMessage ones(final int size, final GqGroup group) {
		checkNotNull(group);
		checkArgument(size > 0, "The message of ones' size must be strictly greater than 0.");

		return Stream.generate(() -> BigInteger.ONE)
				.limit(size)
				.map(one -> GqElement.create(one, group))
				.collect(collectingAndThen(toList(), ElGamalMultiRecipientMessage::new));
	}

	/**
	 * Decrypt a ciphertext to obtain the plaintext message
	 *
	 * @param ciphertext c,	the ciphertext to be decrypted
	 * @param secretKey  sk, the secret key to be used for decrypting
	 * @return the decrypted plaintext message
	 */
	static ElGamalMultiRecipientMessage getMessage(ElGamalMultiRecipientCiphertext ciphertext, ElGamalMultiRecipientPrivateKey secretKey) {

		checkNotNull(ciphertext);
		checkNotNull(secretKey);
		checkArgument(ciphertext.getGroup().getQ().equals(secretKey.getGroup().getQ()), "Ciphertext and secret key must be of the same order");

		int n = ciphertext.size();
		int k = secretKey.size();
		// 0 < k is guaranteed by the checks performed during the construction of the ElGamalMultiRecipientCiphertext
		checkArgument(n <= k, "There can not be more message elements than private key elements.");

		GqElement gamma = ciphertext.getGamma();

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
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		ElGamalMultiRecipientMessage that = (ElGamalMultiRecipientMessage) o;
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
