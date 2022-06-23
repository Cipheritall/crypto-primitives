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

import java.security.Security;
import java.util.Arrays;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import ch.post.it.evoting.cryptoprimitives.hashing.Argon2Config;
import ch.post.it.evoting.cryptoprimitives.hashing.Argon2;
import ch.post.it.evoting.cryptoprimitives.internal.math.RandomService;

public class Argon2Service implements Argon2 {
	private final RandomService randomService;
	private final Argon2Config config;

	public static final int SALT_LENGTH = 16;
	public static final int TAG_LENGTH = 32;

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public Argon2Service(final RandomService randomService, final Argon2Config config) {
		this.randomService = randomService;
		this.config = config;
	}

	@Override
	public byte[] argon2id(byte[] k) {
		final byte[] internalK = Arrays.copyOf(k, k.length); // defensive copy
		final Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
				.withSalt(randomService.randomBytes(SALT_LENGTH))
				.withMemoryPowOfTwo(config.m())
				.withParallelism(config.p())
				.withIterations(config.i())
				.build();

		final Argon2BytesGenerator generator = new Argon2BytesGenerator();
		generator.init(parameters);

		byte[] t = new byte[TAG_LENGTH];
		generator.generateBytes(internalK, t);

		return t;
	}
}
