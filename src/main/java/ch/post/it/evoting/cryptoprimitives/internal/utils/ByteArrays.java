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

package ch.post.it.evoting.cryptoprimitives.internal.utils;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

/**
 * Byte array utilities.
 */
public class ByteArrays {

	private ByteArrays() {
		//Intentional
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
	public static byte[] cutToBitLength(final byte[] byteArray, final int requestedLength) {
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
}
