/*
 * Copyright 2021 Post CH Ltd
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
package ch.post.it.evoting.cryptoprimitives;

import ch.post.it.evoting.cryptoprimitives.math.RandomService;

public final class CryptoPrimitivesService implements CryptoPrimitives {

	private final RandomService randomService = new RandomService();

	@Override
	public String genRandomBase16String(final int length) {
		return randomService.genRandomBase16String(length);
	}

	@Override
	public String genRandomBase32String(final int length) {
		return randomService.genRandomBase32String(length);
	}

	@Override
	public String genRandomBase64String(final int length) {
		return randomService.genRandomBase64String(length);
	}

	public static CryptoPrimitives get() {
		return new CryptoPrimitivesService();
	}
}
