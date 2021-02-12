/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives;

/**
 * Interface to be implemented by classes whose hashable form is a byte array.
 */
public interface HashableByteArray extends Hashable {

	@Override
	byte[] toHashableForm();

	static HashableByteArray from(final byte[] byteArray) {
		return () -> byteArray;
	}
}
