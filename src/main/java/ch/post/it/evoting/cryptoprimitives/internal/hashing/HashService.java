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
package ch.post.it.evoting.cryptoprimitives.internal.hashing;

import static ch.post.it.evoting.cryptoprimitives.internal.utils.ConversionsInternal.byteArrayToInteger;
import static ch.post.it.evoting.cryptoprimitives.internal.utils.ConversionsInternal.integerToByteArray;
import static ch.post.it.evoting.cryptoprimitives.internal.utils.ConversionsInternal.stringToByteArray;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.primitives.Bytes.concat;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

import org.bouncycastle.crypto.digests.SHAKEDigest;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.primitives.Bytes;

import ch.post.it.evoting.cryptoprimitives.hashing.Hash;
import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableBigInteger;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableByteArray;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableList;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableString;
import ch.post.it.evoting.cryptoprimitives.internal.utils.ByteArrays;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.internal.securitylevel.HashFunction;
import ch.post.it.evoting.cryptoprimitives.internal.securitylevel.SecurityLevelConfig;
import ch.post.it.evoting.cryptoprimitives.internal.securitylevel.XOF;

/**
 * Recursive hash service using a default SHA3-256 message digest.
 *
 * <p>This class is thread safe.</p>
 */
public class HashService implements Hash {

	public static final int HASH_LENGTH_BYTES = 32;
	private static final HashService INSTANCE = new HashService(SecurityLevelConfig.getSystemSecurityLevel().getRecursiveHashHashFunction(),
			SecurityLevelConfig.getSystemSecurityLevel().getRecursiveHashToZqXOF());

	private static final byte[] BYTE_ARRAY_PREFIX = new byte[] { 0x00 };
	private static final byte[] BIG_INTEGER_PREFIX = new byte[] { 0x01 };
	private static final byte[] STRING_PREFIX = new byte[] { 0x02 };

	private static final byte[] ARRAY_PREFIX = new byte[] { 0x03 };

	private static final String VALUES_CONTAIN_NULL = "Values contain a null value which cannot be hashed.";
	private static final String NO_VALUES = "Cannot hash no values.";
	private final HashFunction hashFunction;
	private final XOF xof;

	@VisibleForTesting
	HashService(final HashFunction hashFunction, final XOF xof) {
		this.hashFunction = hashFunction;
		this.xof = xof;
	}

	public static HashService getInstance() {
		return INSTANCE;
	}

	/**
	 * See {@link Hash#recursiveHash}
	 */
	@Override
	public byte[] recursiveHash(final Hashable... values) {
		checkNotNull(values);
		checkArgument(Arrays.stream(values).allMatch(Objects::nonNull), VALUES_CONTAIN_NULL);
		checkArgument(values.length != 0, NO_VALUES);

		if (values.length > 1) {
			final HashableList v = HashableList.from(List.of(values));
			return recursiveHash(v);
		} else {
			final Hashable value = values[0];

			if (value instanceof HashableByteArray hashableByteArray) {
				final byte[] w = hashableByteArray.toHashableForm();
				return hashFunction.hash(concat(BYTE_ARRAY_PREFIX, w));
			} else if (value instanceof HashableBigInteger hashableBigInteger) {
				final BigInteger w = hashableBigInteger.toHashableForm();
				checkArgument(w.compareTo(BigInteger.ZERO) >= 0);
				return hashFunction.hash(concat(BIG_INTEGER_PREFIX, integerToByteArray(w)));
			} else if (value instanceof HashableString hashableString) {
				final String w = hashableString.toHashableForm();
				return hashFunction.hash(concat(STRING_PREFIX, stringToByteArray(w)));
			} else if (value instanceof HashableList hashableList) {
				final List<? extends Hashable> w = hashableList.toHashableForm();

				checkArgument(!w.isEmpty(), "Cannot hash an empty list.");

				return hashFunction.hash(
						concat(
							Stream.concat(
								Stream.of(ARRAY_PREFIX),
								w.stream().map(this::recursiveHash)
							).toArray(byte[][]::new)
						)
				);

			} else {
				throw new IllegalArgumentException(String.format("Object of type %s cannot be hashed.", value.getClass()));
			}
		}
	}

	/**
	 * See {@link Hash#hashAndSquare}
	 */
	@Override
	@SuppressWarnings("java:S117")
	public GqElement hashAndSquare(final BigInteger x, final GqGroup group) {
		checkNotNull(x);
		checkNotNull(group);

		checkArgument(this.getHashLength() * Byte.SIZE < group.getQ().bitLength(),
				"The hash length must be smaller than the bit length of this GqGroup's q.");

		final BigInteger q = group.getQ();

		final BigInteger x_h = recursiveHashToZq(q.subtract(BigInteger.ONE), HashableBigInteger.from(x)).getValue().add(BigInteger.ONE);

		return GqElement.GqElementFactory.fromSquareRoot(x_h, group);
	}

	/**
	 * See {@link Hash#recursiveHashToZq}
	 */
	@Override
	@SuppressWarnings("java:S117")
	public ZqElement recursiveHashToZq(final BigInteger exclusiveUpperBound, final Hashable... values) {
		checkNotNull(exclusiveUpperBound);
		checkNotNull(values);
		checkArgument(Arrays.stream(values).allMatch(Objects::nonNull), VALUES_CONTAIN_NULL);

		final int k = values.length;
		final BigInteger q = exclusiveUpperBound;
		final Hashable[] v = values;
		checkArgument(k > 0, NO_VALUES);
		checkArgument(q.compareTo(BigInteger.ZERO) > 0, "The upper bound must be strictly positive.");
		checkArgument(q.bitLength() >= 512, "The exclusive upper bound must have a bit length of at least 512.");

		BigInteger h = byteArrayToInteger(recursiveHashOfLength(q.bitLength(), v));
		while (h.compareTo(q) >= 0) {
			final HashableList h_prependedTo_v = Stream.concat(Stream.of(HashableBigInteger.from(h)), Arrays.stream(v))
					.collect(HashableList.toHashableList());
			h = byteArrayToInteger(recursiveHashOfLength(q.bitLength(), h_prependedTo_v));
		}

		return ZqElement.create(h, new ZqGroup(q));
	}

	/**
	 * Computes the hash of a requested size of multiple (potentially) recursive inputs.
	 *
	 * @param requestedBitLength the requested bit length of the output >= 512.
	 * @param values             the objects to be hashed. Non-empty.
	 * @return a hash of the requested bit length
	 * @throws NullPointerException     if the values are null.
	 * @throws IllegalArgumentException if
	 *                                  <ul>
	 *                                      <li>the values contain null elements</li>
	 *                                      <li>the values are empty</li>
	 *                                      <li>the requested bit length is smaller than 512</li>
	 *                                  </ul>
	 */
	@SuppressWarnings("java:S117")
	@VisibleForTesting
	byte[] recursiveHashOfLength(final int requestedBitLength, final Hashable... values) {
		checkNotNull(values);
		checkArgument(Arrays.stream(values).allMatch(Objects::nonNull), VALUES_CONTAIN_NULL);

		final int k = values.length;
		final int l = requestedBitLength;
		checkArgument(k > 0, NO_VALUES);
		checkArgument(l >= xof.getMinimumOutputLengthBits(), "The requested bit length must be at least %s.", xof.getMinimumOutputLengthBits());

		final int L = (int) Math.ceil(l / 8.0);
		if (k > 1) {
			final HashableList v = HashableList.from(Arrays.asList(values));
			return recursiveHashOfLength(l, v);
		} else {
			final Hashable value = values[0];

			if (value instanceof HashableByteArray hashableByteArray) {
				final byte[] w = hashableByteArray.toHashableForm();
				return ByteArrays.cutToBitLength(shake256(L, concat(BYTE_ARRAY_PREFIX, w)), l);
			} else if (value instanceof HashableBigInteger hashableBigInteger) {
				final BigInteger w = hashableBigInteger.toHashableForm();
				checkArgument(w.compareTo(BigInteger.ZERO) >= 0);
				return ByteArrays.cutToBitLength(shake256(L, concat(BIG_INTEGER_PREFIX, integerToByteArray(w))), l);
			} else if (value instanceof HashableString hashableString) {
				final String w = hashableString.toHashableForm();
				return ByteArrays.cutToBitLength(shake256(L, concat(STRING_PREFIX, stringToByteArray(w))), l);
			} else if (value instanceof HashableList hashableList) {
				final List<? extends Hashable> w = hashableList.toHashableForm();

				checkArgument(!w.isEmpty(), "Cannot hash an empty list.");

				final byte[] h = w.stream().map(w_i -> recursiveHashOfLength(l, w_i)).reduce(ARRAY_PREFIX, Bytes::concat);
				return ByteArrays.cutToBitLength(shake256(L, h), l);
			} else {
				throw new IllegalArgumentException(String.format("Object of type %s cannot be hashed.", value.getClass()));
			}
		}
	}

	/**
	 * @return this message digest length in bytes.
	 */
	public int getHashLength() {
		return HASH_LENGTH_BYTES;
	}

	private byte[] shake256(final int outputLength, final byte[] message) {
		final byte[] result = new byte[outputLength];
		final SHAKEDigest shakeDigest = new SHAKEDigest(256);

		shakeDigest.update(message, 0, message.length);
		shakeDigest.doFinal(result, 0, outputLength);

		return result;
	}
}
