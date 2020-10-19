/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.math;

final class CertaintyLevel {

	private CertaintyLevel() {
	}

	/**
	 * Derive the certainty level from a given bit length.
	 *
	 * @param bitLength The bit length from which to derive the certainty level. Must be a positive integer.
	 * @return The certainty level corresponding to the given {@code bitLength}.
	 */
	static short getCertaintyLevel(final int bitLength) {
		if (bitLength >= 3072) {
			return 128;
		} else if (bitLength >= 2048) {
			return 112;
		} else if (bitLength >= 0) {
			return 80;
		} else {
			throw new IllegalArgumentException("The bit length can not be negative.");
		}
	}

}
