/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.elgamal;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;

/**
 * Represents an ElGamal message containing mutliple elements.
 * <p>
 * This class is immutable.
 */
public class ElGamalMultiRecipientMessage implements ElGamalMultiRecipientObject<GqElement, GqGroup> {

	private final SameGroupVector<GqElement, GqGroup> elements;

	public ElGamalMultiRecipientMessage(final List<GqElement> messageElements) {
		this.elements = new SameGroupVector<>(messageElements);
		checkArgument(!elements.isEmpty(), "An ElGamal message must not be empty.");
	}

	/**
	 * Decrypt a ciphertext to obtain the plaintext message
	 * @param ciphertext	c,	the ciphertext to be decrypted
	 * @param secretKey		sk, the secret key to be used for decrypting
	 * @return	the decrypted plaintext message
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
		if(n == k) {
			messageElements = IntStream.range(0, n)
					.mapToObj(i -> ciphertext.get(i).multiply(gamma.exponentiate(secretKey.get(i).negate())))
					.collect(Collectors.toCollection(LinkedList::new));
		}
		// key compression
		else {
			if(n >= 2) {
				messageElements = IntStream.range(0, n-1)
						.mapToObj(i -> ciphertext.get(i).multiply(gamma.exponentiate(secretKey.get(i).negate())))
						.collect(Collectors.toCollection(LinkedList::new));
			}
			ZqElement compressedKey = IntStream.range(n-1, k)
					.mapToObj(secretKey::get).reduce(ZqElement::add)
					// Because of the precondition n <= k and the else condition n != k we are guaranteed to have at least two elements in the
					// stream, hence the reduce operation is guaranteed to succeed.
					.orElseThrow(() -> new RuntimeException("We should not reach this point."));
			messageElements.add(ciphertext.get(n-1).multiply(gamma.exponentiate(compressedKey.negate())));
		}

		return new ElGamalMultiRecipientMessage(messageElements);
	}

	@Override
	public GqGroup getGroup() {
		//A ElGamalMultiRecipientMessage is never empty
		return this.elements.getGroup();
	}

	@Override
	public int size() {
		return this.elements.size();
	}

	@Override
	public GqElement get(int i) {
		return this.elements.get(i);
	}

	@Override
	public Stream<GqElement> stream() {
		return this.elements.stream();
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
		return elements.equals(that.elements);
	}

	@Override
	public int hashCode() {
		return Objects.hash(elements);
	}
}
