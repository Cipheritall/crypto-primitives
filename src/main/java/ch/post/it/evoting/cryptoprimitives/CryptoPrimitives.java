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
package ch.post.it.evoting.cryptoprimitives;

import java.math.BigInteger;
import java.util.List;

/**
 * Interface exposing all methods that need to be accessed outside of crypto-primitives.
 */
public interface CryptoPrimitives {

	/**
	 * Generates a random string using the Base16 alphabet (RFC 4648).
	 *
	 * @param length l, the length of the string to be generated, in number of chars.
	 * @return a random Base16-encoded string of {@code length} characters. Must be greater than or equal to 1.
	 */
	String genRandomBase16String(final int length);

	/**
	 * Generates a random string using the Base32 alphabet (RFC 4648). The method does not expect to produce Base32 decodable output.
	 *
	 * @param length l, the length of the string to be generated, in number of chars.
	 * @return a random Base32-encoded string of {@code length} characters. Must be greater than or equal to 1.
	 */
	String genRandomBase32String(final int length);

	/**
	 * Generates a random string using the Base64 alphabet (RFC 4648). The method does not expect to produce Base64 decodable output.
	 *
	 * @param length l, the length of the string to be generated, in number of chars.
	 * @return a random Base64-encoded string of {@code length} characters. Must be greater than or equal to 1.
	 */
	String genRandomBase64String(final int length);

	/**
	 * Generates a random BigInteger between 0 (incl.) and {@code upperBound} (excl.).
	 *
	 * @param upperBound m, the upper bound. Must be non null and strictly positive.
	 * @return A random BigInteger <code>r s.t. 0 &le; r &lt; m</code>.
	 */
	BigInteger genRandomInteger(final BigInteger upperBound);

	/**
	 * Generates a list of unique decimal strings.
	 * <p>
	 * Each string in the list is guaranteed to have a different value. Strings that were generated in different calls of this method, might have the
	 * same value.
	 * </p>
	 *
	 * @param desiredCodeLength   l, the desired length of each code. Must be strictly positive.
	 * @param numberOfUniqueCodes n, the number of unique codes. Must be strictly positive.
	 * @return a list of unique decimal strings.
	 */
	List<String> genUniqueDecimalStrings(final int desiredCodeLength, final int numberOfUniqueCodes);
}
