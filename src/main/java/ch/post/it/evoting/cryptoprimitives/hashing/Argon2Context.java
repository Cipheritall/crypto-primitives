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

import static com.google.common.base.Preconditions.checkArgument;

/**
 * Defines the context parameters for the Argon2id algorithm
 *
 * @param m <b>memory usage parameter</b>: defines the memory consumption of the Argon2 algorithm. Memory usage of Argon2id is 2^m KiB.
 * @param p <b>parallelism parameter</b>: defines the parallelism (or number of lanes) as per Argon2 specification.
 * @param i <b>iterationCount parameter</b>: defines the number of iterations (or time parameter) as per Argon2 specification.
 */
public record Argon2Context(int m, int p, int i) {
	public Argon2Context {
		checkArgument(14 <= m && m <= 24,
				"memory outside of expected range: %d is not in [14, 24]", m);
		checkArgument(1 <= p && p <= 16,
				"parallelism outside of expected range: %d is not in [1, 16]", p);
		checkArgument(2 <= i && i <= 256,
				"iterationCount outside of expected range: %d is not in [2, 256]", i);
	}
}
