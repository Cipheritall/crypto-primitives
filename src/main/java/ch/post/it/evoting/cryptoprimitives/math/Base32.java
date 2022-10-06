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
package ch.post.it.evoting.cryptoprimitives.math;

import ch.post.it.evoting.cryptoprimitives.internal.math.Base32Service;

public sealed interface Base32 permits Base32Service {

	/**
	 * Encodes a given byte array as a Base32 string.
	 *
	 * @param byteArray B, the byte array to be encoded.
	 * @return the Base32 string representing the byte array.
	 */
	String base32Encode(final byte[] byteArray);

	/**
	 * Decodes a given Base32 string to a byte array.
	 *
	 * @param string S, the Base32 string to be decoded. Must have a valid Base32 format.
	 * @return the byte array represented by the given Base32 string.
	 * @throws IllegalArgumentException if the given string is not a valid Base32 string.
	 */
	byte[] base32Decode(final String string);
}
