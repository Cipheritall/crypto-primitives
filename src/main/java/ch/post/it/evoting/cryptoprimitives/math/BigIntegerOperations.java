/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.math;

import java.math.BigInteger;

public class BigIntegerOperations {

	private BigIntegerOperations() {
		throw new UnsupportedOperationException("BigIntegerOperations is not supposed to be instantiated");
	}

	public static BigInteger modMultiply(BigInteger n1, BigInteger n2, BigInteger modulus) {
		return (n1.multiply(n2).mod(modulus));
	}

	public static BigInteger modPow(BigInteger base, BigInteger exponent, BigInteger modulus) {
		return base.modPow(exponent, modulus);
	}
}
