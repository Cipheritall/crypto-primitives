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
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import ch.post.it.evoting.cryptoprimitives.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;

/**
 * {@link HashService} to be used by the different mixnet algorithms. This class ensures that the used message digest has an output length smaller
 * than the given maximum bit length.
 */
class MixnetHashService {

	private final HashService delegate;

	/**
	 * Constructs a MixnetHashService, ensuring that the message digest used by {@code hashService} has an output length (in bits) strictly smaller
	 * than {@code maxHashLength}.
	 *
	 * @param hashService   The {@link HashService} to specialize.
	 * @param maxHashLength The max hash length in bits (exclusive).
	 */
	MixnetHashService(final HashService hashService, final int maxHashLength) {
		checkNotNull(hashService);

		final int hashBitLength = hashService.getHashLength() * Byte.SIZE;
		checkArgument(hashBitLength < maxHashLength, "The hash message digest must have an output length strictly smaller than maxHashLength.");

		this.delegate = hashService;
	}

	/**
	 * @see HashService#recursiveHash(Hashable...)
	 */
	byte[] recursiveHash(final Hashable... values) {
		return this.delegate.recursiveHash(values);
	}

}
