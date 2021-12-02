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

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;

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
		checkArgument(Arrays.stream(values).allMatch(Objects::nonNull), "Values contain a null value which cannot be hashed.");
		checkArgument(values.length != 0, "Cannot hash no values.");

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
	 * @return this message digest length in bytes.
	 */
	public int getHashLength() {
		return HASH_LENGTH_BYTES;
	}

}
