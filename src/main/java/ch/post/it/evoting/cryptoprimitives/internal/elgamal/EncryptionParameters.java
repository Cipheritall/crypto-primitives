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
package ch.post.it.evoting.cryptoprimitives.internal.elgamal;

import static ch.post.it.evoting.cryptoprimitives.internal.utils.ConversionsInternal.byteArrayToInteger;
import static ch.post.it.evoting.cryptoprimitives.internal.utils.ConversionsInternal.integerToByteArray;
import static ch.post.it.evoting.cryptoprimitives.internal.utils.ConversionsInternal.stringToByteArray;
import static ch.post.it.evoting.cryptoprimitives.math.GqGroup.isGroupMember;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;

import org.bouncycastle.crypto.digests.SHAKEDigest;

import com.google.common.primitives.Bytes;

import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.internal.securitylevel.SecurityLevelInternal;
import ch.post.it.evoting.cryptoprimitives.internal.securitylevel.SecurityLevelConfig;

/**
 * Provides functionality to create verifiable encryption parameters as a {@link GqGroup}.
 *
 * <p> This class is immutable and thread safe. </p>
 */
public class EncryptionParameters {

	private static final BigInteger ONE = BigInteger.ONE;
	private static final BigInteger TWO = BigInteger.valueOf(2);

	private final SecurityLevelInternal lambda;

	/**
	 * Constructs an instance with a {@link SecurityLevelInternal}.
	 */
	public EncryptionParameters() {
		this.lambda = SecurityLevelConfig.getSystemSecurityLevel();
	}

	/**
	 * Picks verifiable encryption parameters used for the election. The election name is used as the seed.
	 *
	 * @param seed the election name. Must be non-null.
	 * @return a {@link GqGroup} containing the verifiable encryption parameters p, q and g.
	 */
	@SuppressWarnings("java:S117")
	public GqGroup getEncryptionParameters(final String seed) {
		checkNotNull(seed);

		final int certaintyLevel = lambda.getSecurityLevelBits();
		final byte[] seedBytes = stringToByteArray(seed);
		final int pBitLength = lambda.getPBitLength();

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
			if (isGroupMember(BigInteger.valueOf(j), p)) {
				g = BigInteger.valueOf(j);
				break;
			}
		}

		return new GqGroup(p, q, g);
	}

	private byte[] shake128(final byte[] message, final int outputLength) {
		final byte[] result = new byte[outputLength];
		SHAKEDigest shakeDigest = new SHAKEDigest(128);

		shakeDigest.update(message, 0, message.length);
		shakeDigest.doFinal(result, 0, outputLength);

		return result;
	}

}
