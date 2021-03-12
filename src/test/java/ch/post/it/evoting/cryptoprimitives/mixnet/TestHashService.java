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
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static ch.post.it.evoting.cryptoprimitives.ConversionService.byteArrayToInteger;
import static ch.post.it.evoting.cryptoprimitives.ConversionService.integerToByteArray;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import ch.post.it.evoting.cryptoprimitives.HashService;
import ch.post.it.evoting.cryptoprimitives.Hashable;

/**
 * Custom hash service used for testing. The output value of this hash service can be bounded to cope with the small groups used in the tests.
 */
class TestHashService extends MixnetHashService {

	private static HashService hashService;

	private final BigInteger lowerBound;
	private final BigInteger upperBound;

	private TestHashService(final HashService hashService, final BigInteger lowerBound, final BigInteger upperBound) {
		// Ensure the check regarding the output length is satisfied.
		super(hashService, (hashService.getHashLength() * Byte.SIZE) + 1);

		this.lowerBound = lowerBound;
		this.upperBound = upperBound;
	}

	/**
	 * Creates a TestHashService whose output value is between {@code lowerBound} (incl.) and {@code upperBound} (excl.).
	 *
	 * @param lowerBound the lower bound, inclusive.
	 * @param upperBound the upper bound, exclusive.
	 * @return a TestHashService.
	 */
	public static TestHashService create(final BigInteger lowerBound, final BigInteger upperBound) {
		try {
			hashService = new HashService(MessageDigest.getInstance("SHA-256"));
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Failed to instantiate test hash service.");
		}

		return new TestHashService(hashService, lowerBound, upperBound);
	}

	/**
	 * Creates a TestHashService whose output value is between 0 (incl.) and {@code upperBound} (excl.).
	 *
	 * @param upperBound the upper bound, exclusive.
	 * @return a TestHashService.
	 */
	public static TestHashService create(final BigInteger upperBound) {
		return TestHashService.create(BigInteger.ZERO, upperBound);
	}

	/**
	 * Perform the recursive hash, ensuring the output value is within the bounds.
	 *
	 * @param values the values to hash.
	 * @return the bounded hash of the {@code values}.
	 */
	@Override
	public byte[] recursiveHash(final Hashable... values) {
		final BigInteger hashValue = byteArrayToInteger(hashService.recursiveHash(values));
		final BigInteger hashValueInBounds = hashValue.mod(upperBound.subtract(lowerBound)).add(lowerBound);

		return integerToByteArray(hashValueInBounds);
	}

}
