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

public interface Argon2 {

	/**
	 * Computes the Argon2id tag of the input keying material.
	 *
	 * @param inputKeyingMaterial k ∈ B<sup>*</sup>.
	 * @return The tag and the salt represented as a {@link Argon2Hash} (t,s) ∈ B<sup>32</sup> × B<sup>16</sup>.
	 * @throws NullPointerException if the input keying material is null.
	 */
	Argon2Hash genArgon2id(byte[] inputKeyingMaterial);

	/**
	 * Computes the Argon2id tag of the input keying material and the given salt.
	 *
	 * @param inputKeyingMaterial k ∈ B<sup>*</sup>.
	 * @param salt                s k ∈ B<sup>16</sup>.
	 * @return The tag t ∈ B<sup>32</sup>.
	 * @throws NullPointerException if any input is null.
	 */
	byte[] getArgon2id(byte[] inputKeyingMaterial, byte[] salt);
}
