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
package ch.post.it.evoting.cryptoprimitives;

/**
 * Interface exposing all methods that need to be accessed outside of crypto-primitives.
 */
public interface CryptoPrimitive {

	/**
	 * Generate a random Base16 string following RFC 4648.
	 *
	 * @param length l, the length of the string to be generated, in number of chars.
	 * @return A random Base16-encoded string of {@code length} characters. Must be in range (0, 1000).
	 */
	String genRandomBase16String(final int length);

	/**
	 * Generate a random Base32 string following RFC 4648.
	 *
	 * @param length l, the length of the string to be generated, in number of chars.
	 * @return A random Base32-encoded string of {@code length} characters. Must be in range (0, 1000).
	 */
	String genRandomBase32String(final int length);

	/**
	 * Generate a random Base64 string following RFC 4648.
	 *
	 * @param length l, the length of the string to be generated, in number of chars.
	 * @return A random Base64-encoded string of {@code length} characters. Must be in range (0, 1000).
	 */
	String genRandomBase64String(final int length);

	static CryptoPrimitive get() {
		return new CryptoPrimitiveService();
	}

}
