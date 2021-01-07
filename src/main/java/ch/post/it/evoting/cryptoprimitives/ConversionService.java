/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public final class ConversionService {

	private ConversionService() {
		//Intentionally left blank
	}

	/**
	 * Convert a string to a byte array representation.
	 * StringToByteArray algorithm implementation.
	 *
	 * @param s the string to convert.
	 * @return the byte array representation of the string.
	 */
	public static byte[] stringToByteArray(final String s) {
		checkNotNull(s);
		return s.getBytes(StandardCharsets.UTF_8);
	}

	/**
	 * Convert a BigInteger to a byte array representation.
	 *
	 * @param x the positive BigInteger to convert.
	 * @return the byte array representation of this BigInteger.
	 *
	 * NOTE: our implementation slightly deviates from the specifications for performance reasons. Benchmarks show that our implementation is orders of magnitude faster than the
	 * pseudo-code implementation integerToByteArraySpec. Both implementations provide the same result.
	 */
	public static byte[] integerToByteArray(final BigInteger x) {
		checkNotNull(x);
		checkArgument(x.compareTo(BigInteger.ZERO) >= 0);

		// BigInteger#toByteArray gives back a 2s complement representation of the value. Given that we work only with positive BigIntegers, this
		// representation is equivalent to the binary representation, except for a potential extra leading zero byte. (The presence or not of the
		// leading zero depends on the number of bits needed to represent this value).
		byte[] twosComplement = x.toByteArray();
		byte[] result;
		if (twosComplement[0] == 0 && twosComplement.length > 1) {
			result = new byte[twosComplement.length - 1];
			System.arraycopy(twosComplement, 1, result, 0, twosComplement.length - 1);
		} else {
			result = twosComplement;
		}
		return result;
	}

	/**
	 * Do not use.
	 *
	 * <p>This method implements the specification algorithm IntegerToByteArray algorithm implementation and is used in tests to show that it is
	 * equivalent to the more performant method used. </p>
	 **/
	static byte[] integerToByteArraySpec(final BigInteger x) {
		checkNotNull(x);
		checkArgument(x.compareTo(BigInteger.ZERO) >= 0);

		if (x.compareTo(BigInteger.ZERO) == 0) {
			return new byte[1];
		}

		int bitLength = x.bitLength();
		int n = (bitLength + Byte.SIZE - 1) / Byte.SIZE;

		byte[] output = new byte[n];
		BigInteger current = x;
		for(int i = 1; i <= n; i++){
			output[n - i] = current.byteValue();
			current = current.shiftRight(Byte.SIZE);
		}

		return output;
	}

	/**
	 * Convert a byte array to it's BigInteger equivalent.
	 *
	 * @param bytes the byte array to convert to it's BigInteger equivalent.
	 * @return a BigInteger corresponding to the provided byte array representation.
	 */
	public static BigInteger byteArrayToInteger(final byte[] bytes) {
		checkNotNull(bytes);
		return new BigInteger(1, bytes);
	}
}
