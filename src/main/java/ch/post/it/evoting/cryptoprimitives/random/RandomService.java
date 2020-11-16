/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.random;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.security.SecureRandom;

public final class RandomService {

	private final SecureRandom secureRandom;

	/**
	 * Construct a RandomService with a {@link SecureRandom} as its randomness source.
	 */
	public RandomService() {
		this.secureRandom = new SecureRandom();
	}

	/**
	 * Generate a random BigInteger between 0 (incl.) and {@code upperBound} (excl.).
	 *
	 * @param upperBound m, the upper bound.
	 * @return A random BigInteger <code>r s.t. 0 <= r < m</code>.
	 */
	public BigInteger genRandomInteger(final BigInteger upperBound) {
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
	 * Generate a random integer within bounds.
	 *
	 * @param lowerBound a, inclusive.
	 * @param upperbound b, exclusive.
	 * @return a BigInteger within the bounds.
	 */
	public BigInteger genRandomIntegerWithinBounds(BigInteger lowerBound, BigInteger upperbound) {
		checkNotNull(lowerBound);
		checkNotNull(upperbound);
		checkArgument(upperbound.compareTo(lowerBound) > 0,
				"Upper bound %s must be greater than the lower bound %s.", upperbound, lowerBound);

		BigInteger r = genRandomInteger(upperbound.subtract(lowerBound));
		return lowerBound.add(r);
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
