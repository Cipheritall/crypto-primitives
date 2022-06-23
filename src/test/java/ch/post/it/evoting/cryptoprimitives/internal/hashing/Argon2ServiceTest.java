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

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import ch.post.it.evoting.cryptoprimitives.hashing.Argon2Config;
import ch.post.it.evoting.cryptoprimitives.internal.math.RandomService;

@DisplayName("Argon2id")
class Argon2ServiceTest {
	@Test
	@DisplayName("called with known values yield the expected result")
	public void knownValues() {
		// Given
		final RandomService randomService = Mockito.mock(RandomService.class);
		when(randomService.randomBytes(Argon2Service.SALT_LENGTH))
				.thenReturn(HexFormat.of().parseHex("7332424c365a744a44376e784b7a576e"));
		final Argon2Config config = new Argon2Config(14, 1, 2);

		// When
		final Argon2Service service = new Argon2Service(randomService, config);
		final byte[] t = service.argon2id("some password".getBytes(StandardCharsets.UTF_8));

		// Then
		assertArrayEquals(HexFormat.of().parseHex("cdd6160742bc9467e56773cb3debd18982e39a4143409beab7802f6553a242f7"), t);
	}

	@Test
	@DisplayName("accepts the empty byte array")
	public void emptyInput() {
		// Given
		final RandomService randomService = Mockito.mock(RandomService.class);
		when(randomService.randomBytes(Argon2Service.SALT_LENGTH))
				.thenReturn(HexFormat.of().parseHex("7332424c365a744a44376e784b7a576e"));
		final Argon2Config config = new Argon2Config(14, 1, 2);

		// When
		final Argon2Service service = new Argon2Service(randomService, config);
		final byte[] t = service.argon2id(new byte[]{});

		// Then
		assertArrayEquals(HexFormat.of().parseHex("f808c0575c5fdd94184d21b301ad17b82869c553a9760fa6a64cd4648a0f7b23"), t);
	}
}