package ch.post.it.evoting.cryptoprimitives.mixnet;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

class ZeroArgumentTest extends TestGroupSetup {

	@Nested
	@DisplayName("A zeroArgumentBuilder")
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	class ZeroArgumentBuilderTest {

		private final GqElement cA0 = gqGroupGenerator.genMember();
		private final GqElement cBm = gqGroupGenerator.genMember();
		private final SameGroupVector<GqElement, GqGroup> cd = gqGroupGenerator.genRandomGqElementVector(3);
		private final SameGroupVector<ZqElement, ZqGroup> aPrime = zqGroupGenerator.genRandomZqElementVector(2);
		private final SameGroupVector<ZqElement, ZqGroup> bPrime = zqGroupGenerator.genRandomZqElementVector(2);
		private final ZqElement rPrime = zqGroupGenerator.genRandomZqElementMember();
		private final ZqElement sPrime = zqGroupGenerator.genRandomZqElementMember();
		private final ZqElement tPrime = zqGroupGenerator.genRandomZqElementMember();

		@Test
		@DisplayName("built with all initialized fields does not throw")
		void zeroArgumentBuilderValidFields() {
			final ZeroArgument.Builder builder = new ZeroArgument.Builder()
					.withCA0(cA0)
					.withCBm(cBm)
					.withCd(cd)
					.withAPrime(aPrime)
					.withBPrime(bPrime)
					.withRPrime(rPrime)
					.withSPrime(sPrime)
					.withTPrime(tPrime);

			assertDoesNotThrow(builder::build);
		}

		Stream<Arguments> nullArgumentsProvider() {
			return Stream.of(
					Arguments.of(null, cBm, cd, aPrime, bPrime, rPrime, sPrime, tPrime),
					Arguments.of(cA0, null, cd, aPrime, bPrime, rPrime, sPrime, tPrime),
					Arguments.of(cA0, cBm, null, aPrime, bPrime, rPrime, sPrime, tPrime),
					Arguments.of(cA0, cBm, cd, null, bPrime, rPrime, sPrime, tPrime),
					Arguments.of(cA0, cBm, cd, aPrime, null, rPrime, sPrime, tPrime),
					Arguments.of(cA0, cBm, cd, aPrime, bPrime, null, sPrime, tPrime),
					Arguments.of(cA0, cBm, cd, aPrime, bPrime, rPrime, null, tPrime),
					Arguments.of(cA0, cBm, cd, aPrime, bPrime, rPrime, sPrime, null)
			);
		}

		@ParameterizedTest
		@MethodSource("nullArgumentsProvider")
		@DisplayName("built with null fields throws NullPointerException")
		void zeroArgumentBuilderBuildNullFields(final GqElement cA0, final GqElement cBm, final SameGroupVector<GqElement, GqGroup> cd,
				final SameGroupVector<ZqElement, ZqGroup> aPrime, final SameGroupVector<ZqElement, ZqGroup> bPrime, final ZqElement rPrime,
				final ZqElement sPrime, final ZqElement tPrime) {

			final ZeroArgument.Builder builder = new ZeroArgument.Builder()
					.withCA0(cA0)
					.withCBm(cBm)
					.withCd(cd)
					.withAPrime(aPrime)
					.withBPrime(bPrime)
					.withRPrime(rPrime)
					.withSPrime(sPrime)
					.withTPrime(tPrime);

			assertThrows(NullPointerException.class, builder::build);
		}

		@Test
		@DisplayName("built with cd of bad size throws IllegalArgumentException")
		void zeroArgumentBuilderBuildCdBadSize() {
			SameGroupVector<GqElement, GqGroup> badCd = gqGroupGenerator.genRandomGqElementVector(4);
			final ZeroArgument.Builder builder = new ZeroArgument.Builder()
					.withCA0(cA0)
					.withCBm(cBm)
					.withCd(badCd)
					.withAPrime(aPrime)
					.withBPrime(bPrime)
					.withRPrime(rPrime)
					.withSPrime(sPrime)
					.withTPrime(tPrime);

			assertThrows(IllegalArgumentException.class, builder::build);
		}
	}
}
