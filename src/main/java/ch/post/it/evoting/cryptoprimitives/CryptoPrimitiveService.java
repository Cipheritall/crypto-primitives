package ch.post.it.evoting.cryptoprimitives;

/**
 * Interface exposing all methods that need to be accessed outside of crypto-primitives.
 */
public interface CryptoPrimitiveService {

	/**
	 * Generate a random Base16 string following RFC 4648.
	 *
	 * @param length l, the length of the string to be generated, in number of chars.
	 * @return A random Base16-encoded string of {@code length} characters. Must be in range (0, 1000).
	 */
	String genRandomBase16String(final int length);

	/**
	 * Generate a random Base32 string following RFC 4648.
	 *
	 * @param length l, the length of the string to be generated, in number of chars.
	 * @return A random Base32-encoded string of {@code length} characters. Must be in range (0, 1000).
	 */
	String genRandomBase32String(final int length);

	/**
	 * Generate a random Base64 string following RFC 4648.
	 *
	 * @param length l, the length of the string to be generated, in number of chars.
	 * @return A random Base64-encoded string of {@code length} characters. Must be in range (0, 1000).
	 */
	String genRandomBase64String(final int length);

	static CryptoPrimitiveService get() {
		return new CryptoPrimitiveFacade();
	}

}
