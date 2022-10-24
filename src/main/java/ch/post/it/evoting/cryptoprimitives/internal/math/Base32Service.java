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
package ch.post.it.evoting.cryptoprimitives.internal.math;

import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Arrays;

import com.google.common.io.BaseEncoding;

import ch.post.it.evoting.cryptoprimitives.math.Base32;

@SuppressWarnings("java:S117")
public final class Base32Service implements Base32 {

	@Override
	public String base32Encode(final byte[] byteArray) {
		checkNotNull(byteArray);
		final byte[] B = Arrays.copyOf(byteArray, byteArray.length);
		return BaseEncoding.base32().encode(B);
	}

	@Override
	public byte[] base32Decode(final String string) {
		final String S = checkNotNull(string);
		try {
			// The method decode checks the given string is a valid Base32 string.
			return BaseEncoding.base32().decode(S);
		} catch (final IllegalArgumentException e) {
			throw new IllegalArgumentException("The given string is not a valid Base32 string.", e);
		}
	}
}
