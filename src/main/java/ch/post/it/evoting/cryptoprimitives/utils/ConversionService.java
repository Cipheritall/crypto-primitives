/*
 *
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
 *
 */
package ch.post.it.evoting.cryptoprimitives.utils;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

/**
 * <p>This class is thread safe.</p>
 */
public final class ConversionService {

	private ConversionService() {
		//Intentionally left blank
	}

	/**
	 * Converts a string to a byte array representation.
	 *
	 * @param s S, the string to convert.
	 * @return the byte array representation of the string.
	 */
	public static byte[] stringToByteArray(final String s) {
		checkNotNull(s);
		return s.getBytes(StandardCharsets.UTF_8);
	}

	/**
	 * Converts a BigInteger to a byte array representation.
	 * <p>
	 * NOTE: our implementation slightly deviates from the specifications for performance reasons. Benchmarks show that our implementation is orders
	 * of magnitude faster than the pseudo-code implementation integerToByteArraySpec. Both implementations provide the same result.
	 *
	 * @param x the positive BigInteger to convert.
	 * @return the byte array representation of this BigInteger.
	 */
	public static byte[] integerToByteArray(final BigInteger x) {
		checkNotNull(x);
		checkArgument(x.compareTo(BigInteger.ZERO) >= 0);

		// BigInteger#toByteArray gives back a 2s complement representation of the value. Given that we work only with positive BigIntegers, this
		// representation is equivalent to the binary representation, except for a potential extra leading zero byte. (The presence or not of the
		// leading zero depends on the number of bits needed to represent this value).
		final byte[] twosComplement = x.toByteArray();
		final byte[] result;
		if (twosComplement[0] == 0 && twosComplement.length > 1) {
			result = new byte[twosComplement.length - 1];
			System.arraycopy(twosComplement, 1, result, 0, twosComplement.length - 1);
		} else {
			result = twosComplement;
		}
		return result;
	}

	/**
	 * Converts a byte array to its BigInteger equivalent.
	 * <p>
	 * Uses the {@link BigInteger} implementation of the byte array to integer transformation, which is equivalent to the specification of
	 * ByteArrayToInteger.
	 *
	 * @param bytes B, the byte array to convert. Must be non-null and non-empty.
	 * @return a BigInteger corresponding to the provided byte array representation.
	 */
	public static BigInteger byteArrayToInteger(final byte[] bytes) {
		checkNotNull(bytes);
		checkArgument(bytes.length > 0, "The byte array to convert must be non-empty.");
		return new BigInteger(1, bytes);
	}

	/**
	 * Converts a decimal {@link String} representation to a {@link BigInteger} representation.
	 *
	 * @param s S, the decimal {@link String} representation to convert. Not Null, not empty and all characters must be decimal characters.
	 * @return x, the {@link BigInteger} representation of the string.
	 * @throws NullPointerException     if the string s is null
	 * @throws IllegalArgumentException if the string s is empty or not a valid decimal representation of a BigInteger.
	 */
	public static BigInteger stringToInteger(final String s) {
		checkNotNull(s);
		checkArgument(s.length() > 0, "The string to convert cannot be empty.");
		checkArgument(Character.isDigit(s.charAt(0)),
				String.format("The string to convert \"%s\" is not a valid decimal representation of a BigInteger.", s));

		try {
			return new BigInteger(s, 10);
		} catch (NumberFormatException e) {
			throw new IllegalArgumentException(
					String.format("The string to convert \"%s\" is not a valid decimal representation of a BigInteger.", s));
		}
	}

	/**
	 * Converts a {@link BigInteger} representation to a decimal {@link String} representation.
	 *
	 * @param x, the {@link BigInteger} representation to convert. Not Null, positive (including 0).
	 * @return S, the decimal {@link String} representation of the bigInteger.
	 * @throws NullPointerException     if the bigInteger is null
	 * @throws IllegalArgumentException if the bigInteger is not positive
	 */
	public static String integerToString(final BigInteger x) {
		checkNotNull(x);
		checkArgument(x.compareTo(BigInteger.ZERO) >= 0);

		return x.toString(10);
	}

	/**
	 * Converts an {@link Integer} representation to a decimal {@link String} representation.
	 *
	 * @param x, the {@link Integer} representation to convert. Not Null, positive (including 0).
	 * @return S, the decimal {@link String} representation of the Integer.
	 * @throws NullPointerException     if x is null.
	 * @throws IllegalArgumentException if x is not positive.
	 */
	public static String integerToString(final Integer x) {
		checkNotNull(x);
		checkArgument(x >= 0);

		return Integer.toString(x, 10);
	}
}
