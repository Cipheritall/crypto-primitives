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

import ch.post.it.evoting.cryptoprimitives.internal.math.Base16Service;

public sealed interface Base16 permits Base16Service {

	/**
	 * Encodes a given byte array as a Base16 string.
	 *
	 * @param byteArray B, the byte array to be encoded.
	 * @return the Base16 string representing the byte array.
	 */
	String base16Encode(final byte[] byteArray);

	/**
	 * Decodes a given Base16 string to a byte array.
	 *
	 * @param string S, the Base16 string to be decoded. Must have a valid Base16 format.
	 * @return the byte array represented by the given Base16 string.
	 */
	byte[] base16Decode(final String string);
}
