package ch.post.it.evoting.cryptoprimitives;

import static ch.post.it.evoting.cryptoprimitives.ConversionService.toByteArray;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;
import java.util.function.UnaryOperator;
import java.util.stream.Collectors;

public class HashService {
	private final UnaryOperator<byte[]> hashFunction;

	/**
	 * Instantiate a recursive hash service.
	 *
	 * @param messageDigest with which to hash.
	 */
	public HashService(MessageDigest messageDigest) {
		checkNotNull(messageDigest);
		this.hashFunction = messageDigest::digest;
	}

	/**
	 * Compute the hash of multiple (potentially) recursive inputs.
	 *
	 * @param values, objects of the following type:
	 *   <li>byte[]</li>
	 * 	 <li>String</li>
	 * 	 <li>BigInteger</li>
	 * 	 <li>List<?> where every member is of one of the allowed types</li>
	 * @return the hash of the input.
	 *
	 * <p> NOTE:
	 * <li>If the input object(s) are modified during the calculation of the hash, the output is undefined.</li>
	 * <li>It is the caller's responsibility to make sure that the input is not infinite (for example if it contains self-references).</li>
	 * <li>Inputs of different type that have the same byte representation can hash to the same value (for example the empty string and the empty byte
	 * array, or the integer 1 and the byte array 0x1). It is the caller's responsibility to make sure to avoid these collisions by making sure the
	 * domain of each input element is well defined. </li>
	 * 	</p>
	 */
	public byte[] recursiveHash(final Object... values) {
		checkNotNull(values);
		checkArgument(values.length != 0, "Cannot hash no values.");

		if (values.length > 1) {
			return recursiveHash(Arrays.asList(values));
		} else {
			Object value = values[0];
			if (value instanceof byte[]) {
				return this.hashFunction.apply((byte[]) value);
			}
			else if (value instanceof String) {
				return this.hashFunction.apply(toByteArray((String) value));
			}
			else if (value instanceof BigInteger) {
				BigInteger bigInteger = (BigInteger) value;
				checkArgument(bigInteger.compareTo(BigInteger.ZERO) >= 0);
				return this.hashFunction.apply(toByteArray(bigInteger));
			}
			else if (value instanceof List<?>) {
				List<?> list = (List<?>) value;
				checkArgument(!list.isEmpty(), "Cannot hash an empty list.");

				List<byte[]> subHashes = list.stream().map(this::recursiveHash).collect(Collectors.toList());
				int totalSize = subHashes.size() * subHashes.get(0).length;

				byte[] concatenatedSubHashes = new byte[totalSize];
				int offset = 0;
				for (byte[] subHash: subHashes) {
					System.arraycopy(subHash, 0, concatenatedSubHashes, offset, subHash.length);
					offset += subHash.length;
				}

				return this.hashFunction.apply(concatenatedSubHashes);
			}
			else {
				throw new IllegalArgumentException(String.format("Object of type %s cannot be hashed.", values.getClass()));
			}
		}
	}
}
