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

import java.math.BigInteger;
import java.util.stream.IntStream;

import ch.post.it.evoting.cryptoprimitives.math.RandomService;

class PermutationService {

	private final RandomService randomService;

	public PermutationService(final RandomService randomService) {
		checkNotNull(randomService);
		this.randomService = randomService;
	}

	/**
	 * Generates a permutation of integers [0, size).
	 *
	 * @param size N, the strictly positive number of values being permuted.
	 * @return a Permutation object representing an individual permutation.
	 */
	Permutation genPermutation(final int size) {
		checkArgument(size > 0);

		final int[] psi = IntStream.range(0, size).toArray();
		for (int i = 0; i < size; i++) {
			int offset = this.randomService.genRandomInteger(BigInteger.valueOf((long) size - i)).intValueExact();
			int tmp = psi[i];
			psi[i] = psi[i + offset];
			psi[i + offset] = tmp;
		}

		return new Permutation(psi);
	}
}
