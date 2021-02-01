/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.random;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.google.common.io.BaseEncoding;

import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

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
		checkNotNull(upperBound);
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
	public BigInteger genRandomIntegerWithinBounds(final BigInteger lowerBound, final BigInteger upperbound) {
		checkNotNull(lowerBound);
		checkNotNull(upperbound);
		checkArgument(upperbound.compareTo(lowerBound) > 0,
				"Upper bound %s must be greater than the lower bound %s.", upperbound, lowerBound);

		BigInteger r = genRandomInteger(upperbound.subtract(lowerBound));
		return lowerBound.add(r);
	}

	/**
	 * @see ch.post.it.evoting.cryptoprimitives.CryptoPrimitiveService#genRandomBase32String(int)
	 */
	public String genRandomBase32String(final int length) {
		checkArgument(length > 0 && length < 1000);

		// One char can be represented by 5 bits in Base32 encoding. Take advantage of integer truncate instead of ceiling function.
		final int lengthInBytes = (length * 5 + (Byte.SIZE - 1)) / Byte.SIZE;

		// Generate the random bytes, b.
		final byte[] randomBytes = randomBytes(lengthInBytes);

		// Encode to a Base32 String.
		final String encodedString = BaseEncoding.base32().encode(randomBytes);

		// Truncate to desired length.
		return encodedString.substring(0, length);
	}

	/**
	 * @see ch.post.it.evoting.cryptoprimitives.CryptoPrimitiveService#genRandomBase64String(int)
	 */
	public String genRandomBase64String(final int length) {
		checkArgument(length > 0 && length < 1000);

		// One char can be represented by 6 bits in Base64 encoding. Take advantage of integer truncate instead of ceiling function.
		final int lengthInBytes = (length * 6 + (Byte.SIZE - 1)) / Byte.SIZE;

		// Generate the random bytes, b.
		final byte[] randomBytes = randomBytes(lengthInBytes);

		// Encode to a Base64 String.
		final String encodedString = Base64.getEncoder().encodeToString(randomBytes);

		// Truncate to desired length.
		return encodedString.substring(0, length);
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

	/**
	 * Generates a uniformly distributed random exponent within a ZqGroup.
	 *
	 * @param group a ZqGroup (not null)
	 * @return a random element of the group, with value in [2, q).
	 */
	public ZqElement genRandomExponent(final ZqGroup group) {
		checkNotNull(group);

		BigInteger value = genRandomIntegerWithinBounds(BigInteger.valueOf(2), group.getQ());
		return ZqElement.create(value, group);
	}

	/**
	 * Generates a vector (collection) of random {@link ZqElement}s between 0 (incl.) and {@code upperBound} (excl.).
	 *
	 * @param upperBound q
	 * @param length n
	 * @return {@code List<ZqElement>}
	 */
	public List<ZqElement> genRandomVector(final BigInteger upperBound, final int length) {
		checkNotNull(upperBound);
		checkArgument(upperBound.compareTo(BigInteger.ZERO) > 0, "The upper bound should be greater than zero");
		checkArgument(length > 0, "The length should be greater than zero");

		final ZqGroup zqGroup = new ZqGroup(upperBound);

		return  Stream.generate(()->ZqElement.create(genRandomInteger(upperBound),zqGroup))
				.limit(length)
				.collect(Collectors.toList());
	}
}
