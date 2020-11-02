package cryptoprimitives.math;

public final class CertaintyLevel {

	private CertaintyLevel() {
	}

	/**
	 * Derive the certainty level from a bit length. The supported bit lengths are 2048 and 3072.
	 *
	 * @param bitLength The bit length from which to derive the certainty level.
	 * @return The certainty level corresponding to the given {@code bitLength}.
	 */
	public static short getCertaintyLevel(final int bitLength) {
		switch (bitLength) {
		case 2048:
			return 112;
		case 3072:
			return 128;
		default:
			throw new IllegalArgumentException("Bit length does not match a known certainty level.");
		}
	}

}
