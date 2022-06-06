/*
 *
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
 *
 */

package ch.post.it.evoting.cryptoprimitives.utils;

import static ch.post.it.evoting.cryptoprimitives.utils.ByteArrays.cutToBitLength;
import static ch.post.it.evoting.cryptoprimitives.utils.ConversionService.byteArrayToInteger;
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

/**
 * Key derivation function (KDF) service.
 */
public class KDFService {
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
	 * Derives a key from a cryptographically strong pseudo-random key. Uses SHA-256 as a hash function.
	 *
	 * @param pseudoRandomKey    a cryptographically strong pseudo-random key, of byte length greater or equal to 32.
	 * @param contextInformation optional additional context information
	 * @param requiredByteLength the required byte length of the output key, in range 0 (exclusive) to 8160 (inclusive).
	 * @return a cryptographically strong key of length {@code requiredByteLength}
	 * @throws NullPointerException     if any input is null or contains nulls
	 * @throws IllegalArgumentException if any of the preconditions mentioned above are not respected.
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
		checkArgument(L > 0, "Requested KDF byte length is smaller or equal to 0.");
		checkArgument(l_straight >= L, "The pseudo random key length must be greater than the hash function output length.");
		checkArgument(l_curved <= 255 * L, "The required byte length must me smaller than 255 times the hash function output length.");

		final byte[] info =
				Bytes.concat(
						info_vector.stream()
								.map(ConversionService::stringToByteArray)
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
	 * Generates a value in Zq using the Key Derivation Function based on SHA-256.
	 *
	 * @param pseudoRandomKey     a cryptographically strong pseudo-random key, of byte length greater or equal to 32
	 * @param contextInformation  optional additional context information
	 * @param exclusiveUpperBound the requested exclusive upper bound, such that {@code ceil(exclusiveUpperBound / 8) >= 32}
	 * @return an element of Zq
	 * @throws NullPointerException     if any input is null or contains nulls
	 * @throws IllegalArgumentException if any of the preconditions mentioned above are not respected.
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
