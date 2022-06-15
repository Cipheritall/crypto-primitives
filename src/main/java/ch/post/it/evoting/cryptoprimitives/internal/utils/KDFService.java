/*
 * Copyright 2022 Post CH Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package ch.post.it.evoting.cryptoprimitives.internal.utils;

import static ch.post.it.evoting.cryptoprimitives.internal.utils.ByteArrays.cutToBitLength;
import static ch.post.it.evoting.cryptoprimitives.internal.utils.ConversionsInternal.byteArrayToInteger;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.primitives.Bytes;

import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.utils.KeyDerivation;

/**
 * Key derivation function (KeyDerivation) service.
 */
public class KDFService implements KeyDerivation {
	private static final KDFService instance = new KDFService(SHA256Digest::new);
	private final Supplier<Digest> hashSupplier;

	private KDFService(final Supplier<Digest> hashSupplier) {
		this.hashSupplier = hashSupplier;
	}

	public static KDFService getInstance() {
		return instance;
	}

	@VisibleForTesting
	static KDFService testService(final Supplier<Digest> hashSupplier) {
		return new KDFService(hashSupplier);
	}

	/**
	 * See {@link KeyDerivation#KDF}
	 */
	@SuppressWarnings({ "java:S117", "java:S100" })
	public byte[] KDF(final byte[] pseudoRandomKey, final List<String> contextInformation, final int requiredByteLength) {
		checkNotNull(pseudoRandomKey);
		checkNotNull(contextInformation);
		checkArgument(contextInformation.stream().allMatch(Objects::nonNull), "Info contains a null.");

		final int L = this.hashSupplier.get().getDigestSize();
		final byte[] PRK = pseudoRandomKey;
		final int l_straight = PRK.length;
		final List<String> info_vector = List.copyOf(contextInformation);
		final int l_curved = requiredByteLength;

		checkArgument(l_curved > 0, "Requested byte length must be greater than 0. ");
		checkArgument(L > 0, "Requested KeyDerivation byte length is smaller or equal to 0.");
		checkArgument(l_straight >= L, "The pseudo random key length must be greater than the hash function output length.");
		checkArgument(l_curved <= 255 * L, "The required byte length must me smaller than 255 times the hash function output length.");

		final byte[] info =
				Bytes.concat(
						info_vector.stream()
								.map(ConversionsInternal::stringToByteArray)
								.toArray(byte[][]::new)
				);

		return HKDFExpand(PRK, info, l_curved);
	}

	//HKDF-Expand as specified in RFC5869 section 2.3
	//Delegates the implementation to BouncyCastle's implementation
	@SuppressWarnings({ "java:S117", "java:S100" })
	private byte[] HKDFExpand(final byte[] PRK, final byte[] info, final int L) {
		final HKDFBytesGenerator hkdf = new HKDFBytesGenerator(this.hashSupplier.get());
		final HKDFParameters parameters = HKDFParameters.skipExtractParameters(PRK, info);
		hkdf.init(parameters);

		final byte[] OKM = new byte[L];
		hkdf.generateBytes(OKM, 0, L);

		return OKM;
	}

	/**
	 * See {@link KeyDerivation#KDFToZq(byte[], List, BigInteger)}
	 */
	@SuppressWarnings({ "java:S117", "java:S100" })
	public ZqElement KDFToZq(final byte[] pseudoRandomKey, final List<String> contextInformation, final BigInteger exclusiveUpperBound) {
		checkNotNull(pseudoRandomKey);
		checkNotNull(contextInformation);
		checkArgument(contextInformation.stream().allMatch(Objects::nonNull), "Info contains a null.");
		checkNotNull(exclusiveUpperBound);

		final int L = this.hashSupplier.get().getDigestSize();
		final byte[] PRK = pseudoRandomKey;
		final int l_straight = PRK.length;
		final List<String> info = List.copyOf(contextInformation);
		final BigInteger q = exclusiveUpperBound;

		checkArgument(l_straight >= L, "The pseudo random key length must be greater than the hash function output length.");

		final int l_curved = (int) Math.ceil(q.bitLength() / 8.0);
		checkArgument(l_curved >= L);

		byte[] h = KDF(PRK, info, l_curved);
		BigInteger u = byteArrayToInteger(cutToBitLength(h, q.bitLength()));
		while (u.compareTo(q) >= 0) {
			h = KDF(h, info, l_curved);
			u = byteArrayToInteger(cutToBitLength(h, q.bitLength()));
		}

		return ZqElement.create(u, new ZqGroup(q));
	}
}
