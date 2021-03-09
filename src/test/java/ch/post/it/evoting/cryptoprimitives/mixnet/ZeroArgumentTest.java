/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static ch.post.it.evoting.cryptoprimitives.mixnet.ZeroArgument.Builder;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
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

@DisplayName("A ZeroArgument")
class ZeroArgumentTest extends TestGroupSetup {

	private static final int UPPER_BOUND = 10;

	private static int n;

	private static GqElement cA0;
	private static GqElement cBm;
	private static SameGroupVector<GqElement, GqGroup> cd;
	private static SameGroupVector<ZqElement, ZqGroup> aPrime;
	private static SameGroupVector<ZqElement, ZqGroup> bPrime;
	private static ZqElement rPrime;
	private static ZqElement sPrime;
	private static ZqElement tPrime;

	@BeforeAll
	static void setUpAll() {
		final int m = secureRandom.nextInt(UPPER_BOUND) + 1;
		n = secureRandom.nextInt(UPPER_BOUND) + 1;
		final ZeroArgument zeroArgument = new ArgumentGenerator(gqGroup).genZeroArgument(m, n);

		cA0 = zeroArgument.getCA0();
		cBm = zeroArgument.getCBm();
		cd = zeroArgument.getCd();
		aPrime = zeroArgument.getAPrime();
		bPrime = zeroArgument.getBPrime();
		rPrime = zeroArgument.getRPrime();
		sPrime = zeroArgument.getSPrime();
		tPrime = zeroArgument.getTPrime();
	}

	@Nested
	@DisplayName("built with")
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	class BuilderTest {

		@Test
		@DisplayName("all initialized fields does not throw")
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
		@DisplayName("null fields throws NullPointerException")
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
		@DisplayName("inputs from different GqGroup throws IllegalArgumentException")
		void zeroArgumentBuilderDiffGqGroup() {
			final GqElement otherGroupCA0 = otherGqGroupGenerator.genMember();

			final Builder builder = new Builder()
					.withCA0(otherGroupCA0)
					.withCBm(cBm)
					.withCd(cd)
					.withAPrime(aPrime)
					.withBPrime(bPrime)
					.withRPrime(rPrime)
					.withSPrime(sPrime)
					.withTPrime(tPrime);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
			assertEquals("cA0, cBm, cd must belong to the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("inputs from different ZqGroup throws IllegalArgumentException")
		void zeroArgumentBuilderDiffZqGroup() {
			final ZqElement otherGroupRPrime = otherZqGroupGenerator.genRandomZqElementMember();

			final Builder builder = new Builder()
					.withCA0(cA0)
					.withCBm(cBm)
					.withCd(cd)
					.withAPrime(aPrime)
					.withBPrime(bPrime)
					.withRPrime(otherGroupRPrime)
					.withSPrime(sPrime)
					.withTPrime(tPrime);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
			assertEquals("aPrime, bPrime, rPrime, sPrime, tPrime must belong to the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("not compatible GqGroup and ZqGroup throws IllegalArgumentException")
		void zeroArgumentBuilderDiffGqGroupAndZqGroup() {
			final SameGroupVector<ZqElement, ZqGroup> otherGroupAPrime = otherZqGroupGenerator.genRandomZqElementVector(n);
			final SameGroupVector<ZqElement, ZqGroup> otherGroupBPrime = otherZqGroupGenerator.genRandomZqElementVector(n);
			final ZqElement otherGroupRPrime = otherZqGroupGenerator.genRandomZqElementMember();
			final ZqElement otherGroupSPrime = otherZqGroupGenerator.genRandomZqElementMember();
			final ZqElement otherGroupTPrime = otherZqGroupGenerator.genRandomZqElementMember();

			final Builder builder = new Builder()
					.withCA0(cA0)
					.withCBm(cBm)
					.withCd(cd)
					.withAPrime(otherGroupAPrime)
					.withBPrime(otherGroupBPrime)
					.withRPrime(otherGroupRPrime)
					.withSPrime(otherGroupSPrime)
					.withTPrime(otherGroupTPrime);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
			assertEquals("GqGroup and ZqGroup of argument inputs are not compatible.", exception.getMessage());
		}

		@Test
		@DisplayName("aPrime and bPrime of different size throws IllegalArgumentException")
		void zeroArgumentBuilderDiffSizeAPrimeBPrime() {
			final SameGroupVector<ZqElement, ZqGroup> longerAPrime = zqGroupGenerator.genRandomZqElementVector(n + 1);

			final Builder builder = new Builder()
					.withCA0(cA0)
					.withCBm(cBm)
					.withCd(cd)
					.withAPrime(longerAPrime)
					.withBPrime(bPrime)
					.withRPrime(rPrime)
					.withSPrime(sPrime)
					.withTPrime(tPrime);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
			assertEquals("The vectors aPrime and bPrime must have the same size.", exception.getMessage());
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
