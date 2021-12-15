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
package ch.post.it.evoting.cryptoprimitives.hashing;

import static ch.post.it.evoting.cryptoprimitives.ConversionService.byteArrayToInteger;
import static ch.post.it.evoting.cryptoprimitives.ConversionService.integerToByteArray;
import static ch.post.it.evoting.cryptoprimitives.ConversionService.stringToByteArray;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.primitives.Bytes.concat;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.Supplier;
import java.util.stream.Stream;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.primitives.Bytes;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

/**
 * Recursive hash service using a default SHA3-256 message digest.
 *
 * <p>This class is thread safe.</p>
 */
public class HashService {

	public static final int HASH_LENGTH_BYTES = 32;
	private static final HashService Instance = new HashService();

	private static final byte[] BYTE_ARRAY_PREFIX = new byte[] { 0x00 };
	private static final byte[] BIG_INTEGER_PREFIX = new byte[] { 0x01 };
	private static final byte[] STRING_PREFIX = new byte[] { 0x02 };

	private static final String VALUES_CONTAIN_NULL = "Values contain a null value which cannot be hashed.";
	private static final String NO_VALUES = "Cannot hash no values.";

	private static final Supplier<MessageDigest> digestSupplier = () -> {
		try {
			Security.addProvider(new BouncyCastleProvider());
			return MessageDigest.getInstance("SHA3-256", BouncyCastleProvider.PROVIDER_NAME);
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new IllegalStateException("Failed to create the SHA3-256 message digest for the HashService instantiation.");
		}
	};

	@VisibleForTesting
	HashService() {
	}

	public static HashService getInstance() {
		return Instance;
	}

	/**
	 * Computes the hash of multiple (potentially) recursive inputs.
	 *
	 * @param values the objects to be hashed.
	 * @return the hash of the input.
	 *
	 * <p> NOTE:
	 * <ul>
	 * 	<li>If the input object(s) are modified during the calculation of the hash, the output is undefined.</li>
	 * 	<li>It is the caller's responsibility to make sure that the input is not infinite (for example if it contains self-references).</li>
	 * </ul>
	 * @throws IllegalStateException if the creation of the underlying message digest failed.
	 */
	public byte[] recursiveHash(final Hashable... values) {
		checkNotNull(values);
		checkArgument(Arrays.stream(values).allMatch(Objects::nonNull), VALUES_CONTAIN_NULL);
		checkArgument(values.length != 0, NO_VALUES);

		if (values.length > 1) {
			final HashableList v = HashableList.from(ImmutableList.copyOf(values));
			return recursiveHash(v);
		} else {
			final Hashable value = values[0];

			final MessageDigest messageDigest = digestSupplier.get();
			if (value instanceof HashableByteArray) {
				final byte[] w = ((HashableByteArray) value).toHashableForm();
				return messageDigest.digest(concat(BYTE_ARRAY_PREFIX, w));
			} else if (value instanceof HashableBigInteger) {
				final BigInteger w = ((HashableBigInteger) value).toHashableForm();
				checkArgument(w.compareTo(BigInteger.ZERO) >= 0);
				return messageDigest.digest(concat(BIG_INTEGER_PREFIX, integerToByteArray(w)));
			} else if (value instanceof HashableString) {
				final String w = ((HashableString) value).toHashableForm();
				return messageDigest.digest(concat(STRING_PREFIX, stringToByteArray(w)));
			} else if (value instanceof HashableList) {
				final ImmutableList<? extends Hashable> w = ((HashableList) value).toHashableForm();

				checkArgument(!w.isEmpty(), "Cannot hash an empty list.");

				if (w.size() == 1) {
					return recursiveHash(w.get(0));
				}

				w.stream().map(this::recursiveHash).forEachOrdered(messageDigest::update);

				return messageDigest.digest();
			} else {
				throw new IllegalArgumentException(String.format("Object of type %s cannot be hashed.", value.getClass()));
			}
		}
	}

	/**
	 * Hashes and squares a BigInteger to return a GqElement.
	 *
	 * @param x     The BigInteger to be hashed. Must be non-null.
	 * @param group The group to which the returned GqElement has to belong. Must be non-null.
	 * @return the squared hash of x as GqElement.
	 * @throws NullPointerException     if any argument is null
	 * @throws IllegalArgumentException if the bit length of the group's q is smaller than the hash length in bits
	 */
	@SuppressWarnings("java:S117")
	public GqElement hashAndSquare(final BigInteger x, final GqGroup group) {
		checkNotNull(x);
		checkNotNull(group);

		checkArgument(this.getHashLength() * Byte.SIZE < group.getQ().bitLength(),
				"The hash length must be smaller than the bit length of this GqGroup's q.");

		final BigInteger q = group.getQ();

		final BigInteger x_h = recursiveHashToZq(q.subtract(BigInteger.ONE), HashableBigInteger.from(x)).add(BigInteger.ONE);

		return GqElement.GqElementFactory.fromSquareRoot(ZqElement.create(x_h, ZqGroup.sameOrderAs(group)), group);
	}

	/**
	 * Computes the hash in Z<sub>q</sub> of multiple (potentially) recursive inputs.
	 *
	 * @param exclusiveUpperBound the exlusive upper bound for the hash to be returned. Must be strictly positive.
	 * @param values              the objects to be hashed. Must be non-null.
	 * @return the result of the hashing as a {@link BigInteger} smaller than q
	 * @throws NullPointerException     if any of the arguments is null
	 * @throws IllegalArgumentException if
	 *                                  <ul>
	 *                                      <li>values contain null elements</li>
	 *                                      <li>values are empty</li>
	 *                                      <li>the requested bit length is smaller than 512</li>
	 *                                  </ul>
	 */
	@SuppressWarnings("java:S117")
	public BigInteger recursiveHashToZq(final BigInteger exclusiveUpperBound, final Hashable... values) {
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

		return h;
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
		checkArgument(l >= 512, "The requested bit length must be at least 512.");

		final int L = (int) Math.ceil(l / 8.0);
		if (k > 1) {
			final HashableList v = HashableList.from(Arrays.asList(values));
			return recursiveHashOfLength(l, v);
		} else {
			final Hashable value = values[0];

			if (value instanceof HashableByteArray) {
				final byte[] w = ((HashableByteArray) value).toHashableForm();
				return cutToBitLength(shake256(L, concat(BYTE_ARRAY_PREFIX, w)), l);
			} else if (value instanceof HashableBigInteger) {
				final BigInteger w = ((HashableBigInteger) value).toHashableForm();
				checkArgument(w.compareTo(BigInteger.ZERO) >= 0);
				return cutToBitLength(shake256(L, concat(BIG_INTEGER_PREFIX, integerToByteArray(w))), l);
			} else if (value instanceof HashableString) {
				final String w = ((HashableString) value).toHashableForm();
				return cutToBitLength(shake256(L, concat(STRING_PREFIX, stringToByteArray(w))), l);
			} else if (value instanceof HashableList) {
				final ImmutableList<? extends Hashable> w = ((HashableList) value).toHashableForm();

				checkArgument(!w.isEmpty(), "Cannot hash an empty list.");

				final int j = w.size() - 1;
				if (j == 0) {
					return recursiveHashOfLength(l, w.get(0));
				} else {
					final byte[] h = w.stream().map(w_i -> recursiveHashOfLength(l, w_i)).reduce(new byte[] {}, Bytes::concat);

					return cutToBitLength(shake256(L, h), l);
				}

			} else {
				throw new IllegalArgumentException(String.format("Object of type %s cannot be hashed.", value.getClass()));
			}
		}
	}

	/**
	 * Cuts the given byte array to the requested bit length
	 *
	 * @param byteArray       the byte array to be cut
	 * @param requestedLength the length in bits to which the array is to be cut. Greater than 0 and not greater than the byte array's bit length.
	 * @return the byte array cut to the requested length
	 * @throws NullPointerException     if the given byte array is null
	 * @throws IllegalArgumentException if the requested length is not within the required range
	 */
	@SuppressWarnings("java:S117")
	@VisibleForTesting
	byte[] cutToBitLength(final byte[] byteArray, final int requestedLength) {
		checkNotNull(byteArray);

		final byte[] B = byteArray;
		final int n = requestedLength;

		checkArgument(0 < n, "The requested length must be strictly positive");
		checkArgument(n <= (B.length * Byte.SIZE), "The requested length must not be greater than the bit length of the byte array");

		final int length = (int) Math.ceil(n / (double) Byte.SIZE);
		final int offset = B.length - length;
		final byte[] B_prime = new byte[length];
		if (n % 8 != 0) {
			B_prime[0] = (byte) (B[offset] & (byte) (Math.pow(2, n % 8) - 1));
		} else {
			B_prime[0] = B[offset];
		}

		for (int i = 1; i < length; i++) {
			B_prime[i] = B[offset + i];
		}
		return B_prime;
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
