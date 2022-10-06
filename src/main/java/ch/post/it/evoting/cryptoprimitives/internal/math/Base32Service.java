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

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.common.io.BaseEncoding;

import ch.post.it.evoting.cryptoprimitives.math.Base32;

@SuppressWarnings("java:S117")
public final class Base32Service implements Base32 {

	private static final String BASE32_REGEX = "^([A-Z2-7]{8})*(([A-Z2-7]{8})*|[A-Z2-7]{7}=|[A-Z2-7]{5}={3}|[A-Z2-7]{4}={4}|[A-Z2-7]{2}={6})$";
	private static final Pattern BASE32_PATTERN = Pattern.compile(BASE32_REGEX);

	@Override
	public String base32Encode(final byte[] byteArray) {
		checkNotNull(byteArray);
		final byte[] B = Arrays.copyOf(byteArray, byteArray.length);
		return BaseEncoding.base32().encode(B);
	}

	@Override
	public byte[] base32Decode(final String string) {
		final String S = checkNotNull(string);
		checkArgument(isBase32(S), "The given string is not a valid Base32 string.");
		return BaseEncoding.base32().decode(S);
	}

	private boolean isBase32(final String string) {
		final Matcher matcher = BASE32_PATTERN.matcher(string);
		return matcher.matches();
	}
}
