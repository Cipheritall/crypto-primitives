package ch.post.it.evoting.cryptoprimitives.random;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.security.SecureRandom;

final class RandomService {

	private final SecureRandom secureRandom;

	/**
	 * Construct a RandomService with a {@link SecureRandom} as its randomness source.
	 */
	RandomService() {
		this.secureRandom = new SecureRandom();
	}

	/**
	 * Generate a random BigInteger between 0 (incl.) and {@code upperBound} (excl.).
	 *
	 * @param upperBound m, the upper bound.
	 * @return A random BigInteger <code>r s.t. 0 <= r < m</code>.
	 */
	BigInteger genRandomInteger(final BigInteger upperBound) {
		checkNotNull(upperBound, "The upper bound can not be null.");
		checkArgument(upperBound.compareTo(BigInteger.ZERO) > 0, "The upper bound must a be a positive integer greater than 0.");

		final int bitLength = upperBound.bitLength();

		BigInteger randomBigInteger;
		do {
			// This constructor internally masks the excess generated bits.
			randomBigInteger = new BigInteger(bitLength, secureRandom);
		} while (randomBigInteger.compareTo(upperBound) >= 0);

		return randomBigInteger;
	}

	/**
	 * Generate an array of {@code byteLength} random bytes.
	 *
	 * @param byteLength The number of bytes to generate.
	 * @return An array of {@code byteLength} random bytes.
	 */
	private byte[] randomBytes(final int byteLength) {
		final byte[] randomBytes = new byte[byteLength];
		secureRandom.nextBytes(randomBytes);

		return randomBytes;
	}

}
