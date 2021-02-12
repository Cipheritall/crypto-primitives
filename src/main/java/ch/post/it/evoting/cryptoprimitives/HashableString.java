/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives;

/**
 * Interface to be implemented by classes whose hashable form is a single {@link String}.
 */
public interface HashableString extends Hashable {

	@Override
	String toHashableForm();

	static HashableString from(final String string) {
		return () -> string;
	}
}
