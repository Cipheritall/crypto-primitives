/*
 *
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
 *
 */
package ch.post.it.evoting.cryptoprimitives.utils;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

@State(Scope.Benchmark)
public class ConversionServiceBenchmark {

	private static final SecureRandom secureRandom = new SecureRandom();

	@Param({ "2048", "3072" })
	static int bitLength;

	@Benchmark
	@Warmup(iterations = 4, time = 5)
	@Fork(value = 1)
	@Measurement(iterations = 4, time = 5)
	public byte[] bigIntegerToByteArrayUsingJdk(final MyState state) {
		return ConversionService.integerToByteArray(state.randomBigInteger);
	}

	@Benchmark
	@Warmup(iterations = 4, time = 5)
	@Fork(value = 1)
	@Measurement(iterations = 4, time = 5)
	public byte[] bigIntegerToByteArray(final MyState state) {
		return ConversionServiceEquivalenceTest.integerToByteArraySpec(state.randomBigInteger);
	}

	@State(Scope.Thread)
	public static class MyState {

		private BigInteger randomBigInteger;

		@Setup(Level.Invocation)
		public void genRandomBigInteger() {
			randomBigInteger = new BigInteger(bitLength, secureRandom);
		}
	}
}
