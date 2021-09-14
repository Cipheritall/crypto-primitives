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
package ch.post.it.evoting.cryptoprimitives.elgamal;

import static ch.post.it.evoting.cryptoprimitives.ConversionService.byteArrayToInteger;
import static ch.post.it.evoting.cryptoprimitives.ConversionService.integerToByteArray;
import static ch.post.it.evoting.cryptoprimitives.ConversionService.stringToByteArray;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;

import org.bouncycastle.crypto.digests.SHAKEDigest;

import com.google.common.primitives.Bytes;

import ch.post.it.evoting.cryptoprimitives.SecurityLevel;
import ch.post.it.evoting.cryptoprimitives.SecurityLevelConfig;
import ch.post.it.evoting.cryptoprimitives.math.BigIntegerOperationsService;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;

/**
 * Provides functionality to create verifiable encryption parameters as a {@link GqGroup}.
 */
class EncryptionParameters {

	private static final BigInteger ONE = BigInteger.ONE;
	private static final BigInteger TWO = BigInteger.valueOf(2);
	private static final SHAKEDigest shakeDigest = new SHAKEDigest(128);

	private final SecurityLevel lambda;

	/**
	 * Constructs an instance with a {@link SecurityLevel}.
	 */
	EncryptionParameters() {
		this.lambda = SecurityLevelConfig.getSystemSecurityLevel();
	}

	/**
	 * Picks verifiable encryption parameters used for the election. The election name is used as the seed.
	 *
	 * @param seed the election name. Must be non-null.
	 * @return a {@link GqGroup} containing the verifiable encryption parameters p, q and g.
	 */
	@SuppressWarnings("java:S117")
	GqGroup getEncryptionParameters(final String seed) {
		checkNotNull(seed);

		final int certaintyLevel = lambda.getStrength();
		final byte[] seedBytes = stringToByteArray(seed);
		final int pBitLength = lambda.getBitLength();

		int i = 0;
		BigInteger q;
		do {
			final byte[] message = Bytes.concat(seedBytes, integerToByteArray(BigInteger.valueOf(i)));
			final byte[] q_b_hat = shake128(message, pBitLength / Byte.SIZE);
			final byte[] q_b = Bytes.concat(new byte[] { 0x01 }, q_b_hat);
			q = byteArrayToInteger(q_b).shiftRight(2); // The BigInteger is positive so shiftRight is equivalent to a logical right shift.
			q = q.add(ONE).subtract(q.mod(TWO));
			i++;
		} while (!q.isProbablePrime(certaintyLevel) || !TWO.multiply(q).add(ONE).isProbablePrime(certaintyLevel));

		final BigInteger p = TWO.multiply(q).add(ONE);

		BigInteger g = null;
		for (int j = 2; j <= 4; j++) {
			if (isGroupMember(p, q, BigInteger.valueOf(j))) {
				g = BigInteger.valueOf(j);
				break;
			}
		}

		return new GqGroup(p, q, g);
	}

	/**
	 * Checks if {@code value} is a member of the group defined by {@code p} and {@code q}.
	 */
	private boolean isGroupMember(final BigInteger p, final BigInteger q, final BigInteger value) {
		return BigIntegerOperationsService.modExponentiate(value, q, p).compareTo(BigInteger.ONE) == 0;
	}

	private byte[] shake128(final byte[] message, final int outputLength) {
		final byte[] result = new byte[outputLength];

		shakeDigest.update(message, 0, message.length);
		shakeDigest.doFinal(result, 0, outputLength);

		return result;
	}

}
