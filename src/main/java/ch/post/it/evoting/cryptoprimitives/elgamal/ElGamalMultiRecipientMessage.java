/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.elgamal;

import java.util.List;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;

/**
 * Represents an ElGamal message containing mutliple elements.
 * <p>
 * This class is immutable.
 */
public class ElGamalMultiRecipientMessage extends SameGroupVector<GqElement, GqGroup> {
	public ElGamalMultiRecipientMessage(final List<GqElement> messageElements) {
		super(messageElements);
	}
}
