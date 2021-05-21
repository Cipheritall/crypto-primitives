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
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.function.UnaryOperator;

import com.google.common.collect.ImmutableList;
import com.google.common.primitives.Bytes;

import ch.post.it.evoting.cryptoprimitives.ConversionService;

public class HashService {

	private final UnaryOperator<byte[]> hashFunction;
	private final int hashLength;

	/**
	 * Instantiates a recursive hash service.
	 *
	 * @param messageDigest with which to hash.
	 */
	public HashService(final MessageDigest messageDigest) {
		checkNotNull(messageDigest);
		this.hashFunction = messageDigest::digest;
		this.hashLength = messageDigest.getDigestLength();
	}

	/**
	 * Instantiates a recursive hash service with a default SHA-256 message digest.
	 *
	 * @throws IllegalStateException if the creation of the SHA-256 message digest failed.
	 */
	public HashService() {
		final MessageDigest messageDigest;
		try {
			messageDigest = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("Failed to create the SHA-256 message digest for the HashService instantiation.");
		}

		this.hashFunction = messageDigest::digest;
		this.hashLength = messageDigest.getDigestLength();
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
	 * 	<li>Inputs of different type that have the same byte representation can hash to the same value (for example the empty string and the empty
	 * byte array, or the integer 1 and the byte array 0x1). It is the caller's responsibility to make sure to avoid these collisions by making sure
	 * the domain of each input element is well defined. </li>
	 * </ul>
	 */
	public byte[] recursiveHash(final Hashable... values) {
		checkNotNull(values);
		checkArgument(values.length != 0, "Cannot hash no values.");
		checkArgument(Arrays.stream(values).allMatch(Objects::nonNull), "Values contain a null value which cannot be hashed.");

		if (values.length > 1) {
			final HashableList valuesList = HashableList.from(ImmutableList.copyOf(values));
			return recursiveHash(valuesList);
		} else {
			final Hashable value = values[0];

			if (value instanceof HashableByteArray) {
				final byte[] byteArrayValue = ((HashableByteArray) value).toHashableForm();
				return this.hashFunction.apply(byteArrayValue);
			} else if (value instanceof HashableString) {
				final String stringValue = ((HashableString) value).toHashableForm();
				return this.hashFunction.apply(ConversionService.stringToByteArray(stringValue));
			} else if (value instanceof HashableBigInteger) {
				final BigInteger bigIntegerValue = ((HashableBigInteger) value).toHashableForm();
				checkArgument(bigIntegerValue.compareTo(BigInteger.ZERO) >= 0);
				return this.hashFunction.apply(integerToByteArray(bigIntegerValue));
			} else if (value instanceof HashableList) {
				final HashableList list = (HashableList) value;
				final List<? extends Hashable> listOfHashables = list.toHashableForm();

				checkArgument(!listOfHashables.isEmpty(), "Cannot hash an empty list.");

				if (listOfHashables.size() == 1) {
					return recursiveHash(listOfHashables.get(0));
				}

				// Compute and concatenate hashes of list elements.
				final byte[] concatenatedHashes = Bytes.concat(listOfHashables.stream().map(this::recursiveHash).toArray(byte[][]::new));

				return this.hashFunction.apply(concatenatedHashes);
			} else {
				throw new IllegalArgumentException(String.format("Object of type %s cannot be hashed.", value.getClass()));
			}
		}
	}

	/**
	 * @return this message digest length in bytes.
	 */
	public int getHashLength() {
		return this.hashLength;
	}

}
