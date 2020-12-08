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
	public static byte[] toByteArray(final String s) {
		checkNotNull(s);
		return s.getBytes(StandardCharsets.UTF_8);
	}

	/**
	 * Convert a BigInteger to a byte array representation.
	 * IntegerToByteArray algorithm implementation.
	 *
	 * @param x the positive BigInteger to convert.
	 * @return the byte array representation of this BigInteger.
	 */
	public static byte[] toByteArray(final BigInteger x) {
		checkNotNull(x);
		checkArgument(x.compareTo(BigInteger.ZERO) >= 0);

		if (x.compareTo(BigInteger.ZERO) == 0) {
			return new byte[1];
		}

		final BigInteger mask = BigInteger.valueOf(256);

		int bitLength = x.bitLength();
		int n = (bitLength + Byte.SIZE - 1) / Byte.SIZE;

		byte[] output = new byte[n];
		BigInteger current = x;
		for(int i = 1; i <= n; i++){
			// BigInteger operations represent values using the two's complement representation. Hence, for a value in the range [127, 256) we cannot
			// use BigInteger.byteValueExact(). Since the value we are converting is positive and smaller than 256 (the mask), we can convert it to an
			// int and then cast to a byte to get the binary representation.
			output[n - i] = (byte) current.mod(mask).intValueExact();
			current = current.shiftRight(Byte.SIZE);
		}

		return output;
	}

	/**
	 * Convert a byte array to it's BigInteger equivalent.
	 * ByteArrayToInteger algorithm implementation.
	 *
	 * @param bytes the byte array to convert to it's BigInteger equivalent.
	 * @return a BigInteger corresponding to the provided byte array representation.
	 */
	public static BigInteger fromByteArray(final byte[] bytes) {
		checkNotNull(bytes);
		return new BigInteger(1, bytes);
	}
}
