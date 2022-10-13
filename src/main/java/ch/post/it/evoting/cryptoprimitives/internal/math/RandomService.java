/*
 * Copyright 2022 Post CH Ltd
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
package ch.post.it.evoting.cryptoprimitives.internal.math;

import static ch.post.it.evoting.cryptoprimitives.internal.utils.ConversionsInternal.integerToString;
import static ch.post.it.evoting.cryptoprimitives.math.GroupVector.toGroupVector;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Strings;

import ch.post.it.evoting.cryptoprimitives.math.Base16;
import ch.post.it.evoting.cryptoprimitives.math.Base32;
import ch.post.it.evoting.cryptoprimitives.math.Base64;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.Random;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

/**
 * This class is thread safe.
 */
public class RandomService implements Random {

	private final SecureRandom secureRandom;
	private final Base16 base16;
	private final Base32 base32;
	private final Base64 base64;

	/**
	 * Constructs a RandomService with a {@link SecureRandom} as its randomness source.
	 */
	public RandomService() {
		this.secureRandom = new SecureRandom();
		this.base16 = new Base16Service();
		this.base32 = new Base32Service();
		this.base64 = new Base64Service();
	}

	@VisibleForTesting
	RandomService(final SecureRandom secureRandom) {
		this.secureRandom = secureRandom;
		this.base16 = new Base16Service();
		this.base32 = new Base32Service();
		this.base64 = new Base64Service();
	}

	/**
	 * @see Random#genRandomInteger(BigInteger)
	 * This implementation yields the same result as the specification's pseudo-code and we have a
	 * corresponding unit test that asserts the equivalence of the two implementations.
	 */
	public BigInteger genRandomInteger(final BigInteger upperBound) {
		checkNotNull(upperBound);
		checkArgument(upperBound.compareTo(BigInteger.ZERO) > 0, "The upper bound must a be a positive integer greater than 0.");
		final BigInteger m = upperBound;

		final int bitLength = m.bitLength();

		BigInteger r;
		do {
			// This constructor internally masks the excess generated bits.
			r = new BigInteger(bitLength, secureRandom);
		} while (r.compareTo(m) >= 0);

		return r;
	}

	/**
	 * @see Random#genRandomBase16String(int)
	 */
	public String genRandomBase16String(final int length) {
		checkArgument(length > 0);
		final int l = length;

		// One char can be represented by 4 bits in Base16 encoding.
		final int l_bytes = (int) Math.ceil(4.0 * l / Byte.SIZE);

		// Generate the random bytes, b.
		final byte[] b = randomBytes(l_bytes);

		// Encode to a Base16 String and truncate to desired length.
		return truncate(base16.base16Encode(b), l);
	}

	/**
	 * @see Random#genRandomBase32String(int)
	 */
	public String genRandomBase32String(final int length) {
		checkArgument(length > 0);
		final int l = length;

		// One char can be represented by 5 bits in Base32 encoding.
		final int l_bytes = (int) Math.ceil(5.0 * l / Byte.SIZE);

		// Generate the random bytes, b.
		final byte[] b = randomBytes(l_bytes);

		// Encode to a Base32 String and truncate to desired length.
		return truncate(base32.base32Encode(b), l);
	}

	/**
	 * @see Random#genRandomBase64String(int)
	 */
	public String genRandomBase64String(final int length) {
		checkArgument(length > 0);
		final int l = length;

		// One char can be represented by 6 bits in Base64 encoding
		final int l_bytes = (int) Math.ceil(6.0 * l / Byte.SIZE);

		// Generate the random bytes
		final byte[] b = randomBytes(l_bytes);

		// Encode to a Base64 String and truncate to desired length.
		return truncate(base64.base64Encode(b), l);
	}

	/**
	 * @see Random#genUniqueDecimalStrings(int, int)
	 */
	public List<String> genUniqueDecimalStrings(final int desiredCodeLength, final int numberOfUniqueCodes) {
		final int l = desiredCodeLength;
		final int n = numberOfUniqueCodes;
		checkArgument(l > 0, "The desired length of the unique codes must be strictly positive.");
		checkArgument(n > 0, "The number of unique codes must be strictly positive.");

		checkArgument(n <= Math.pow(10, l), "There cannot be more than 10^l codes.");

		final List<String> codes = new ArrayList<>(n);
		final BigInteger m = BigInteger.valueOf(10).pow(l);
		while (codes.size() < n) {
			final BigInteger x = genRandomInteger(m);
			final String c = leftPad(integerToString(x), l, '0');
			if (!codes.contains(c)) {
				codes.add(c);
			}
		}

		return codes;
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

		final BigInteger q = upperBound;
		final int n = length;

		final ZqGroup zqGroup = new ZqGroup(q);

		return Stream.generate(() -> ZqElement.create(genRandomInteger(q), zqGroup))
				.limit(n)
				.collect(toGroupVector());
	}

	/**
	 * Generates an array of {@code byteLength} random bytes.
	 *
	 * @param byteLength The number of bytes to generate.
	 * @return An array of {@code byteLength} random bytes.
	 */
	public byte[] randomBytes(final int byteLength) {
		final byte[] randomBytes = new byte[byteLength];
		secureRandom.nextBytes(randomBytes);

		return randomBytes;
	}

	/**
	 * Pads a string to the desired length by adding the given character to the left of the string.
	 *
	 * @param string              S, the string to be padded. Must be of size > 0.
	 * @param desiredStringLength l, the desired string length. Must be greater than the string length.
	 * @param paddingCharacter    c, the character to be used for the padding.
	 * @return the string padded to the desired length by adding the padding character the needed number of times on the left-hand side
	 * @throws NullPointerException     if the string is null
	 * @throws IllegalArgumentException if the desired length is smaller than the length of the string to be padded
	 */
	@VisibleForTesting
	String leftPad(final String string, final int desiredStringLength, final char paddingCharacter) {
		checkNotNull(string);
		checkArgument(!string.isEmpty(), "The string to be padded must contain at least one character.");

		final int k = string.length();
		final int l = desiredStringLength;
		checkArgument(k <= l, "The desired string length must not be smaller than the string.");

		// This method is equivalent to the specification
		return Strings.padStart(string, desiredStringLength, paddingCharacter);
	}

	/**
	 * Implements the Truncate algorithm.
	 *
	 * @param string S, the string to be truncated. Must be non-null and non-empty.
	 * @param length l, the desired length for the truncated string. Must be strictly positive.
	 * @return S<sup>'</sup>, the truncated string.
	 * @throws NullPointerException     if the input string is null.
	 * @throws IllegalArgumentException if
	 *                                  <ul>
	 *                                      <li>the input string is empty.</li>
	 *                                      <li>the input length is not strictly positive.</li>
	 *                                      <li>the input string length is smaller than the input length.</li>
	 *                                  </ul>
	 */
	@VisibleForTesting
	String truncate(final String string, final int length) {

		final String S = checkNotNull(string);
		final int u = S.length();
		final int l = length;

		checkArgument(u > 0, "The input string must be non-empty. [u: %s]", u);
		checkArgument(l > 0, "The input length must be strictly positive. [l: %s]", l);

		// Require.
		checkArgument(l <= u, "The input length must be smaller or equal to the input string length. [l: %s, u: %s]", l, u);

		// Operation. This implementation yields the same result as the specification's pseudo-code and we have a corresponding unit test that asserts the equivalence of the two implementations.
		return S.substring(0, l);
	}
}
