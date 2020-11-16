/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.math;

import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;

import ch.post.it.evoting.cryptoprimitives.random.RandomService;

/**
 * Utilities to generate random exponents.
 */
public class ExponentGenerator {

	private ExponentGenerator() {
	}

	/**
	 * Generates a uniformly distributed random exponent within a ZqGroup.
	 *
	 * @param group         a ZqGroup (not null)
	 * @param randomService the entropy source used to generate the value of the element. Not null.
	 * @return a random element of the group, with value in [2, q).
	 */
	public static ZqElement genRandomExponent(final ZqGroup group, final RandomService randomService) {
		checkNotNull(group);
		checkNotNull(randomService);

		BigInteger value = randomService.genRandomIntegerWithinBounds(BigInteger.valueOf(2), group.getQ());
		return ZqElement.create(value, group);
	}
}
