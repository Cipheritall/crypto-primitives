/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives;

/**
 * Represents an object that is hashable by the recursive hash algorithm. This interface must NOT be implemented directly. Instead objects should
 * implement the sub-interfaces representing the particular hashable form of a Java type.
 * <p>
 * The allowed types returned by the {@code toHashableForm} method are the following:
 * <ul>
 *     <li>byte[]</li>
 *     <li>String</li>
 *     <li>BigInteger</li>
 *     <li>List<Hashable></li>
 * </ul>
 *
 * @see ch.post.it.evoting.cryptoprimitives.HashService#recursiveHash(Hashable...)
 */
public interface Hashable {

	/**
	 * Converts an object to its hashable form. The allowed return types are defined by the recursive hash algorithm.
	 *
	 * @return the hashable form of the object.
	 * @see ch.post.it.evoting.cryptoprimitives.HashService#recursiveHash(Hashable...)
	 */
	Object toHashableForm();

}
