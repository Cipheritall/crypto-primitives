/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.elgamal;

import java.util.stream.Stream;

import ch.post.it.evoting.cryptoprimitives.GroupVectorElement;
import ch.post.it.evoting.cryptoprimitives.math.GroupElement;
import ch.post.it.evoting.cryptoprimitives.math.MathematicalGroup;

/**
 * Defines a common API for El Gamal multi-recipient objects.
 */
interface ElGamalMultiRecipientObject<E extends GroupElement<G>, G extends MathematicalGroup<G>> extends GroupVectorElement<G> {

	 @Override
	 G getGroup();

	/**
	 * @return the size of this actor.
	 */
	 int size();

	/**
	 * @return the ith element of this actor.
	 */
	E get(int i);

	/**
	 * @return an ordered stream of this object's elements.
	 */
	Stream<E> stream();
}
