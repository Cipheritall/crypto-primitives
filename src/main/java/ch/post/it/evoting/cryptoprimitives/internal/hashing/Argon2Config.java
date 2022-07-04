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
package ch.post.it.evoting.cryptoprimitives.internal.hashing;

import java.util.Arrays;

/**
 * Defines the config values for the Argon2id algorithm.
 *
 * @param tagLength
 * @param salt
 * @param memory
 * @param parallelism
 * @param iterations
 */
record Argon2Config(int tagLength, byte[] salt, int memory, int parallelism, int iterations) {
	@Override
	public boolean equals(final Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}

		Argon2Config that = (Argon2Config) o;

		if (tagLength != that.tagLength) {
			return false;
		}
		if (memory != that.memory) {
			return false;
		}
		if (parallelism != that.parallelism) {
			return false;
		}
		if (iterations != that.iterations) {
			return false;
		}
		return Arrays.equals(salt, that.salt);
	}

	@Override
	public int hashCode() {
		int result = tagLength;
		result = 31 * result + Arrays.hashCode(salt);
		result = 31 * result + memory;
		result = 31 * result + parallelism;
		result = 31 * result + iterations;
		return result;
	}

	@Override
	public String toString() {
		return "Argon2Config{" +
				"tagLength=" + tagLength +
				", salt=" + Arrays.toString(salt) +
				", memory=" + memory +
				", parallelism=" + parallelism +
				", iterations=" + iterations +
				'}';
	}
}
