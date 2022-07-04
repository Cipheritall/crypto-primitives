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

import static com.google.common.base.Preconditions.checkNotNull;

import java.security.Security;
import java.util.Arrays;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import ch.post.it.evoting.cryptoprimitives.hashing.Argon2;
import ch.post.it.evoting.cryptoprimitives.hashing.Argon2Context;
import ch.post.it.evoting.cryptoprimitives.hashing.Argon2Hash;
import ch.post.it.evoting.cryptoprimitives.internal.math.RandomService;

public class Argon2Service implements Argon2 {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	private final RandomService randomService;
	private final Argon2Context config;

	public Argon2Service(final RandomService randomService, final Argon2Context config) {
		this.randomService = randomService;
		this.config = config;
	}

	/**
	 * See {@link Argon2#genArgon2id}
	 */
	@Override
	public Argon2Hash genArgon2id(final byte[] inputKeyingMaterial) {
		checkNotNull(inputKeyingMaterial);
		final byte[] k = Arrays.copyOf(inputKeyingMaterial, inputKeyingMaterial.length);

		final byte[] s = randomService.randomBytes(16);
		final byte[] t = getArgon2id(k, s);

		return new Argon2Hash(t, s);
	}

	/**
	 * See {@link Argon2#getArgon2id}
	 */
	@Override
	public byte[] getArgon2id(final byte[] inputKeyingMaterial, final byte[] salt) {
		checkNotNull(inputKeyingMaterial);
		checkNotNull(salt);

		final byte[] k = Arrays.copyOf(inputKeyingMaterial, inputKeyingMaterial.length);
		final byte[] s = Arrays.copyOf(salt, salt.length);
		final int m = config.m();
		final int p = config.p();
		final int i = config.i();

		final Argon2Config c = new Argon2Config(32, s, m, p, i);
		return argon2id(c, k);
	}

	private byte[] argon2id(final Argon2Config c, final byte[] k) {
		final Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
				.withSalt(c.salt())
				.withMemoryPowOfTwo(c.memory())
				.withParallelism(c.parallelism())
				.withIterations(c.iterations())
				.build();

		final Argon2BytesGenerator generator = new Argon2BytesGenerator();
		generator.init(parameters);

		byte[] t = new byte[c.tagLength()];
		generator.generateBytes(k, t);

		return t;
	}
}
