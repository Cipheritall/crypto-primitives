/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.elgamal;

import static com.google.common.base.Preconditions.checkArgument;

import java.math.BigInteger;
import java.util.List;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

/**
 * Encapsulates an ElGamal multi recipient private key with N elements, each corresponding to a different recipient. The order of the elements must
 * match that of the elements of the associated public key.
 *
 * <p>Instances of this class are immutable. </p>
 */
public final class ElGamalMultiRecipientPrivateKey extends SameGroupVector<ZqElement, ZqGroup> {

	/**
	 * Creates an {@link ElGamalMultiRecipientPrivateKey} object.
	 *
	 * @param keyElements <p>the list of private key Zq keyElements, which must satisfy the conditions of a {@link SameGroupVector} and
	 *                    the following:
	 *                    <li>no element must be equal to 0</li>
	 *                    <li>no element must be equal to 1</li></p>
	 */
	public ElGamalMultiRecipientPrivateKey(final List<ZqElement> keyElements) {
		super(ImmutableList.copyOf(keyElements));
		checkArgument(keyElements.stream().map(ZqElement::getValue).allMatch(value -> value.compareTo(BigInteger.ZERO) != 0),
				"An ElGamal private key cannot contain a 0 valued element.");
		checkArgument(keyElements.stream().map(ZqElement::getValue).allMatch(value -> value.compareTo(BigInteger.ONE) != 0),
				"An ElGamal private key cannot contain a 1 valued element.");
	}
}
