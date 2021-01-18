/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives;

import ch.post.it.evoting.cryptoprimitives.math.MathematicalGroup;

/**
 * Marker interface for types that have a mathematical group associated.
 *
 * @param <G> the group type associated.
 */
public interface HasGroup<G extends MathematicalGroup<G>> {
	/**
	 * @return the group this element belongs to.
	 */
	G getGroup();
}
