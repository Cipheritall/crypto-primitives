package ch.post.it.evoting.cryptoprimitives;

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

	@Param({"2048", "3072"})
	public static int bitLength;

	@State(Scope.Thread)
	public static class MyState {

		private BigInteger randomBigInteger;

		@Setup(Level.Invocation)
		public void genRandomBigInteger() {
			randomBigInteger = new BigInteger(bitLength, secureRandom);
		}
	}

	@Benchmark
	@Warmup(iterations = 4, time = 5)
	@Fork(value = 1)
	@Measurement(iterations = 4, time = 5)
	public byte[] bigIntegerToByteArrayUsingJdk(MyState state) {
		return ConversionService.integerToByteArray(state.randomBigInteger);
	}

	@Benchmark
	@Warmup(iterations = 4, time = 5)
	@Fork(value = 1)
	@Measurement(iterations = 4, time = 5)
	public byte[] bigIntegerToByteArray(MyState state) {
		return ConversionService.integerToByteArraySpec(state.randomBigInteger);
	}
}
