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
package ch.post.it.evoting.cryptoprimitives.internal.mixnet;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.IntStream;

import ch.post.it.evoting.cryptoprimitives.internal.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.mixnet.Permutation;

/**
 * <p>This class is thread safe.</p>
 */
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
		final int N = size;
		checkArgument(N > 0);

		final ArrayList<Integer> pi = IntStream.range(0, N)
				.boxed()
				.collect(ArrayList::new, ArrayList::add, ArrayList::addAll);
		for (int i = 0; i < N; i++) {
			final int offset = genRandomInteger(N - i);
			final int tmp = pi.get(i);
			pi.set(i, pi.get(i + offset));
			pi.set(i + offset, tmp);
		}

		return new Permutation(List.copyOf(pi));
	}

	/*
	 * Generates a random integer with an int bound.
	 * */
	private int genRandomInteger(final int bound) {
		final BigInteger boundAsBigInteger = BigInteger.valueOf(bound);
		final BigInteger randomValue = this.randomService.genRandomInteger(boundAsBigInteger);
		return randomValue.intValueExact(); //It is guaranteed to be in the int range as the bound is an int
	}
}
