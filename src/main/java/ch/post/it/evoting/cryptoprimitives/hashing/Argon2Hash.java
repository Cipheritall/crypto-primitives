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
package ch.post.it.evoting.cryptoprimitives.hashing;

import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Arrays;

/**
 * An argon2 hash composed of a tag and a salt.
 *
 * <p>Instances of this class are immutable.</p>
 */
public record Argon2Hash(byte[] tag, byte[] salt) {

	public Argon2Hash(final byte[] tag, final byte[] salt) {
		checkNotNull(tag);
		checkNotNull(salt);
		this.tag = Arrays.copyOf(tag, tag.length);
		this.salt = Arrays.copyOf(salt, salt.length);
	}

	public byte[] getTag() {
		return Arrays.copyOf(tag, tag.length);
	}

	public byte[] getSalt() {
		return Arrays.copyOf(salt, salt.length);
	}

	@Override
	public boolean equals(final Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		final Argon2Hash that = (Argon2Hash) o;
		return Arrays.equals(tag, that.tag) && Arrays.equals(salt, that.salt);
	}

	@Override
	public int hashCode() {
		int result = Arrays.hashCode(tag);
		result = 31 * result + Arrays.hashCode(salt);
		return result;
	}

	@Override
	public String toString() {
		return "Argon2Hash{" +
				"tag=" + Arrays.toString(tag) +
				", salt=" + Arrays.toString(salt) +
				'}';
	}
}
