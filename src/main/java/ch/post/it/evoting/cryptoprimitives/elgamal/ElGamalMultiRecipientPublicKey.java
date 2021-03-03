/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.elgamal;

import static com.google.common.base.Preconditions.checkArgument;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.Hashable;
import ch.post.it.evoting.cryptoprimitives.HashableList;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;

/**
 * Encapsulates an ElGamal multi recipient public key with N elements, each corresponding to a different recipient. The order of the elements must
 * match that of the elements of the associated public key.
 *
 * <p>A recipient ElGamal public key is related to its associated ElGamal private key by the following
 * operation: <code>publicKey = g <sup>privateKey</sup> mod p</code>, where g is the generator and p the modulo of the Gq group to which the public
 * key belongs, and privateKey is a member of Zq (notice that Gq and Zq are of the same order). </p>
 *
 * <p>Instances of this class are immutable. </p>
 */
public final class ElGamalMultiRecipientPublicKey implements ElGamalMultiRecipientObject<GqElement, GqGroup>, HashableList {

	private final SameGroupVector<GqElement, GqGroup> publicKeyElements;

	/**
	 * Creates an {@link ElGamalMultiRecipientPublicKey} object.
	 *
	 * @param keyElements <p>the list of public key Gq group publicKeyElements, which must satisfy the conditions of a {@link SameGroupVector} and
	 *                    the following:
	 *                    <li>not be empty</li>
	 *                    <li>no element must be equal to 1</li>
	 *                    <li>no element must be equal to the generator of the group they belong to</li></p>
	 */
	public ElGamalMultiRecipientPublicKey(final List<GqElement> keyElements) {
		this.publicKeyElements = SameGroupVector.from(keyElements);
		checkArgument(!publicKeyElements.isEmpty(), "An ElGamal public key must not be empty.");
		checkArgument(keyElements.stream().map(GqElement::getValue).allMatch(value -> value.compareTo(BigInteger.ONE) != 0),
				"An ElGamal public key cannot contain a 1 valued element.");
		checkArgument(keyElements.stream().allMatch(element -> element.getValue().compareTo(element.getGroup().getGenerator().getValue()) != 0),
				"An ElGamal public key cannot contain an element value equal to the group generator.");
	}

	@Override
	public GqGroup getGroup() {
		//An ElGamal public key is not empty
		return this.publicKeyElements.getGroup();
	}

	@Override
	public int size() {
		return this.publicKeyElements.size();
	}

	@Override
	public GqElement get(int i) {
		return this.publicKeyElements.get(i);
	}

	@Override
	public Stream<GqElement> stream() {
		return this.publicKeyElements.stream();
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		ElGamalMultiRecipientPublicKey publicKey = (ElGamalMultiRecipientPublicKey) o;
		return publicKeyElements.equals(publicKey.publicKeyElements);
	}

	@Override
	public int hashCode() {
		return Objects.hash(publicKeyElements);
	}

	@Override
	public ImmutableList<? extends Hashable> toHashableForm() {
		return this.publicKeyElements.toHashableForm();
	}
}
