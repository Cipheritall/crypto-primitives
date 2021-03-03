/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives;

import ch.post.it.evoting.cryptoprimitives.math.MathematicalGroup;

/**
 * Elements of a GroupVector or GroupMatrix.
 *
 * @param <G> the group type associated.
 */
public interface GroupVectorElement<G extends MathematicalGroup<G>> {
	/**
	 * @return the group this element belongs to.
	 */
	G getGroup();

	/**
	 * @return the size of this element.
	 */
	int size();
}
