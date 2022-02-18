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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("A HashableByteArray")
class HashableByteArrayTest {

	@Test
	@DisplayName("correctly makes a copy of the input byte array")
	void hashableByteArrayFromMakesCopy() {
		final byte[] bytes = { 0b01, 0b10, 0b11 };
		final byte[] expected = { 0b01, 0b10, 0b11 };

		final HashableByteArray hashableByteArray = HashableByteArray.from(bytes);

		assertArrayEquals(expected, hashableByteArray.toHashableForm());

		// Modify original byte array.
		bytes[0] = 0b11;

		assertArrayEquals(expected, hashableByteArray.toHashableForm());
	}

}
