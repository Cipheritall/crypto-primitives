/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives;

import com.google.common.collect.ImmutableList;

/**
 * Interface to be implemented by classes whose hashable form is an {@link ImmutableList} of {@link Hashable} objects.
 */
public interface HashableList extends Hashable {

	@Override
	ImmutableList<? extends Hashable> toHashableForm();

	static HashableList from(final ImmutableList<Hashable> list) {
		return () -> list;
	}
}
