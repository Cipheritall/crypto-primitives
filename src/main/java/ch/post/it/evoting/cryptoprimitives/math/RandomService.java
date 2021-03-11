/*
 * Copyright 2021 Post CH Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ch.post.it.evoting.cryptoprimitives.math;

import static ch.post.it.evoting.cryptoprimitives.GroupVector.toGroupVector;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.stream.Stream;

import com.google.common.io.BaseEncoding;

import ch.post.it.evoting.cryptoprimitives.GroupVector;

public class RandomService {

	private final SecureRandom secureRandom;

	/**
	 * Constructs a RandomService with a {@link SecureRandom} as its randomness source.
	 */
	public RandomService() {
		this.secureRandom = new SecureRandom();
	}

	/**
	 * Generates a random BigInteger between 0 (incl.) and {@code upperBound} (excl.).
	 *
	 * @param upperBound m, the upper bound. Must be non null and strictly positive.
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
	 * Generates a random integer within bounds.
	 * <p>
	 * The {@code lowerBound} and {@code upperBound} parameters must comply with the following:
	 * <ul>
	 *     <li>The upper bound must be greater than the lower bound.</li>
	 * </ul>
	 *
	 * @param lowerBound a, inclusive. Must be non null.
	 * @param upperbound b, exclusive. Must be non null.
	 * @return a BigInteger within the bounds.
	 */
	BigInteger genRandomIntegerWithinBounds(final BigInteger lowerBound, final BigInteger upperbound) {
		checkNotNull(lowerBound);
		checkNotNull(upperbound);
		checkArgument(upperbound.compareTo(lowerBound) > 0,
				"Upper bound %s must be greater than the lower bound %s.", upperbound, lowerBound);

		final BigInteger r = genRandomInteger(upperbound.subtract(lowerBound));
		return lowerBound.add(r);
	}

	/**
	 * @see ch.post.it.evoting.cryptoprimitives.CryptoPrimitives#genRandomBase16String(int)
	 */
	public String genRandomBase16String(final int length) {
		checkArgument(length > 0);

		// One char can be represented by 4 bits in Base16 encoding.
		final int lengthInBytes = (int) Math.ceil(4.0 * length / Byte.SIZE);

		// Generate the random bytes, b.
		final byte[] randomBytes = randomBytes(lengthInBytes);

		// Encode to a Base16 String.
		final String encodedString = BaseEncoding.base16().encode(randomBytes);

		// Truncate to desired length.
		return encodedString.substring(0, length);
	}

	/**
	 * @see ch.post.it.evoting.cryptoprimitives.CryptoPrimitives#genRandomBase32String(int)
	 */
	public String genRandomBase32String(final int length) {
		checkArgument(length > 0);

		// One char can be represented by 5 bits in Base32 encoding.
		final int lengthInBytes = (int) Math.ceil(5.0 * length / Byte.SIZE);

		// Generate the random bytes, b.
		final byte[] randomBytes = randomBytes(lengthInBytes);

		// Encode to a Base32 String.
		final String encodedString = BaseEncoding.base32().encode(randomBytes);

		// Truncate to desired length.
		return encodedString.substring(0, length);
	}

	/**
	 * @see ch.post.it.evoting.cryptoprimitives.CryptoPrimitives#genRandomBase64String(int)
	 */
	public String genRandomBase64String(final int length) {
		checkArgument(length > 0);

		// One char can be represented by 6 bits in Base64 encoding.
		final int lengthInBytes = (int) Math.ceil(6.0 * length / Byte.SIZE);

		// Generate the random bytes, b.
		final byte[] randomBytes = randomBytes(lengthInBytes);

		// Encode to a Base64 String.
		final String encodedString = Base64.getEncoder().encodeToString(randomBytes);

		// Truncate to desired length.
		return encodedString.substring(0, length);
	}

	/**
	 * Generates a uniformly distributed random exponent within the group of integers modulo q (but excluding 0 and 1).
	 *
	 * @param upperBound q, the upper bound. Must be non null and greater than 2.
	 * @return a random element of the group, with value in [2, q).
	 */
	public ZqElement genRandomExponent(final BigInteger upperBound) {
		checkNotNull(upperBound);

		final BigInteger two = BigInteger.valueOf(2);

		checkArgument(upperBound.compareTo(two) > 0, "The provided upperBound element must be greater than 2.");

		final BigInteger value = genRandomIntegerWithinBounds(two, upperBound);

		return ZqElement.create(value, new ZqGroup(upperBound));
	}

	/**
	 * Generates a vector (collection) of random {@link ZqElement}s between 0 (incl.) and {@code upperBound} (excl.).
	 *
	 * @param upperBound q, the exclusive upper bound. Must be non null and strictly positive.
	 * @param length     n, the desired length. Must be strictly positive.
	 * @return {@code List<ZqElement>}
	 */
	public GroupVector<ZqElement, ZqGroup> genRandomVector(final BigInteger upperBound, final int length) {
		checkNotNull(upperBound);
		checkArgument(upperBound.compareTo(BigInteger.ZERO) > 0, "The upper bound should be greater than zero");
		checkArgument(length > 0, "The length should be greater than zero");

		final ZqGroup zqGroup = new ZqGroup(upperBound);

		return Stream.generate(() -> ZqElement.create(genRandomInteger(upperBound), zqGroup))
				.limit(length)
				.collect(toGroupVector());
	}

	/**
	 * Generates an array of {@code byteLength} random bytes.
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