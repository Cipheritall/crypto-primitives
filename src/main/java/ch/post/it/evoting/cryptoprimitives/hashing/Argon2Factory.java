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

import ch.post.it.evoting.cryptoprimitives.internal.hashing.Argon2Service;
import ch.post.it.evoting.cryptoprimitives.internal.math.RandomService;

public class Argon2Factory {
	private static final Argon2Factory INSTANCE = new Argon2Factory();

	private final RandomService randomService;

	private Argon2Factory() {
		randomService = new RandomService();
	}

	public static Argon2 createArgon2(Argon2Context config) {
		return new Argon2Service(INSTANCE.randomService, config);
	}
}
