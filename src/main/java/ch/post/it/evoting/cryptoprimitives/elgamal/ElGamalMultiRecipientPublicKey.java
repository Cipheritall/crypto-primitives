/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.elgamal;

import static com.google.common.base.Preconditions.checkArgument;

import java.math.BigInteger;
import java.util.List;

import com.google.common.collect.ImmutableList;

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
public final class ElGamalMultiRecipientPublicKey extends SameGroupVector<GqElement, GqGroup> {

	/**
	 * Creates an {@link ElGamalMultiRecipientPublicKey} object.
	 *
	 * @param keyElements <p>the list of public key Gq group elements, which must satisfy the conditions of a {@link SameGroupVector} and
	 *                    the following:
	 *                    <li>no element must be equal to 1</li>
	 *                    <li>no element must be equal to the generator of the group they belong to</li></p>
	 */
	public ElGamalMultiRecipientPublicKey(final List<GqElement> keyElements) {
		super(ImmutableList.copyOf(keyElements));
		checkArgument(keyElements.stream().map(GqElement::getValue).allMatch(value -> value.compareTo(BigInteger.ONE) != 0),
				"An ElGamal public key cannot contain a 1 valued element.");
		checkArgument(keyElements.stream().allMatch(element -> element.getValue().compareTo(element.getGroup().getGenerator().getValue()) != 0),
				"An ElGamal public key cannot contain an element value equal to the group generator.");
	}
}
