/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.math;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;
import java.util.stream.IntStream;

import com.google.common.collect.ImmutableList;

public class BigIntegerOperations {

	private static final String MODULUS_CHECK_MESSAGE = "The modulus must be greater than 1";

	private BigIntegerOperations() {
		throw new UnsupportedOperationException("BigIntegerOperations is not supposed to be instantiated");
	}

	/**
	 * Multiply two {@link BigInteger}s and take the modulus.
	 *
	 * @param n1		the multiplier
	 * @param n2		the multiplicand
	 * @param modulus	the modulus > 1
	 * @return	the product n1 &times; n2 mod modulus
	 */
	public static BigInteger modMultiply(final BigInteger n1, final BigInteger n2, final BigInteger modulus) {
		checkNotNull(n1);
		checkNotNull(n2);
		checkNotNull(modulus);
		checkArgument(modulus.compareTo(BigInteger.ONE) > 0, MODULUS_CHECK_MESSAGE);

		return n1.multiply(n2).mod(modulus);
	}

	/**
	 * Exponentiate a {@link BigInteger} by another and take the modulus. If the exponent is negative, base and modulus must be relatively prime.
	 *
	 * @param base		the base
	 * @param exponent	the exponent
	 * @param modulus	the modulus > 1
	 * @return	the power base<sup>exponent</sup> mod modulus
	 */
	public static BigInteger modExponentiate(final BigInteger base, final BigInteger exponent, final BigInteger modulus) {
		checkNotNull(base);
		checkNotNull(exponent);
		checkNotNull(modulus);
		checkArgument(exponent.compareTo(BigInteger.ZERO) >= 0 || base.gcd(modulus).equals(BigInteger.ONE),
				"When the exponent is negative, base and modulus must be relatively prime");
		checkArgument(modulus.compareTo(BigInteger.ONE) > 0, MODULUS_CHECK_MESSAGE);

		return base.modPow(exponent, modulus);
	}

	/**
	 * Exponentiate the elements of a list of {@link BigInteger}s by the elements of a second list and multiply the resulting terms.
	 * If an exponent is negative, then the corresponding base must be relatively prime to the modulus.
	 * This operations needs both lists to be of equal size.
	 *
	 * @param bases		the list of base values
	 * @param exponents	the list of exponent values
	 * @param modulus	the modulus > 1
	 * @return	the product of the powers b[0]^e[0] * b[1]^e[1] * ... * b[n-1]^e[n-1] mod modulus
	 */
	public static BigInteger multiModExp(final List<BigInteger> bases, final List<BigInteger> exponents, final BigInteger modulus) {
		checkNotNull(bases);
		checkArgument(bases.stream().allMatch(Objects::nonNull), "Elements must not contain nulls");
		ImmutableList<BigInteger> basesCopy = ImmutableList.copyOf(bases);
		checkArgument(!basesCopy.isEmpty(), "Bases must be non empty.");

		checkNotNull(exponents);
		checkArgument(exponents.stream().allMatch(Objects::nonNull), "Elements must not contain nulls");
		ImmutableList<BigInteger> exponentsCopy = ImmutableList.copyOf(exponents);

		// The next check assures also that exponentsCopy is not empty
		checkArgument(basesCopy.size() == exponentsCopy.size(), "Bases and exponents must have the same size");
		checkArgument(modulus.compareTo(BigInteger.ONE) > 0, MODULUS_CHECK_MESSAGE);

		int numElements = basesCopy.size();

		return IntStream.range(0, numElements)
				.mapToObj(i -> modExponentiate(basesCopy.get(i), exponentsCopy.get(i), modulus))
				.reduce(BigInteger.ONE, (a, b) -> modMultiply(a, b, modulus));
	}
}
