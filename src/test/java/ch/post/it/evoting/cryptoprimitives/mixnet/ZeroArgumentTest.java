package ch.post.it.evoting.cryptoprimitives.mixnet;

import static ch.post.it.evoting.cryptoprimitives.mixnet.ZeroArgument.ZeroArgumentBuilder;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GroupTestData;

class ZeroArgumentTest {

	@Nested
	@DisplayName("A zeroArgumentBuilder")
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	class ZeroArgumentBuilderTest {

		private final GqGroup gqGroup = GroupTestData.getGqGroup();
		private final ZqGroup zqGroup = ZqGroup.sameOrderAs(gqGroup);

		private final GqElement cA0 = GqElement.create(BigInteger.ONE, gqGroup);
		private final GqElement cBm = GqElement.create(BigInteger.ONE, gqGroup);
		private final SameGroupVector<GqElement, GqGroup> cd = SameGroupVector.of(GqElement.create(BigInteger.ONE, gqGroup));
		private final SameGroupVector<ZqElement, ZqGroup> aPrime = SameGroupVector.of(ZqElement.create(BigInteger.ONE, zqGroup));
		private final SameGroupVector<ZqElement, ZqGroup> bPrime = SameGroupVector.of(ZqElement.create(BigInteger.ONE, zqGroup));
		private final ZqElement rPrime = ZqElement.create(BigInteger.ONE, zqGroup);
		private final ZqElement sPrime = ZqElement.create(BigInteger.ONE, zqGroup);
		private final ZqElement tPrime = ZqElement.create(BigInteger.ONE, zqGroup);

		@Test
		@DisplayName("built with all initialized fields does not throw")
		void zeroArgumentBuilderValidFields() {
			final ZeroArgumentBuilder builder = new ZeroArgumentBuilder()
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

			final ZeroArgumentBuilder builder = new ZeroArgumentBuilder()
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
	}
}
