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

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.TestGroupSetup;

@DisplayName("A ZeroArgument")
class ZeroArgumentTest extends TestGroupSetup {

	private static final int UPPER_BOUND = 10;

	private static int n;

	private static GqElement cA0;
	private static GqElement cBm;
	private static GroupVector<GqElement, GqGroup> cd;
	private static GroupVector<ZqElement, ZqGroup> aPrime;
	private static GroupVector<ZqElement, ZqGroup> bPrime;
	private static ZqElement rPrime;
	private static ZqElement sPrime;
	private static ZqElement tPrime;

	@BeforeAll
	static void setUpAll() {
		final int m = secureRandom.nextInt(UPPER_BOUND) + 1;
		n = secureRandom.nextInt(UPPER_BOUND) + 1;
		final ZeroArgument zeroArgument = new TestArgumentGenerator(gqGroup).genZeroArgument(m, n);

		cA0 = zeroArgument.get_c_A_0();
		cBm = zeroArgument.get_c_B_m();
		cd = zeroArgument.get_c_d();
		aPrime = zeroArgument.get_a_prime();
		bPrime = zeroArgument.get_b_prime();
		rPrime = zeroArgument.get_r_prime();
		sPrime = zeroArgument.get_s_prime();
		tPrime = zeroArgument.get_t_prime();
	}

	@Nested
	@DisplayName("built with")
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	class BuilderTest {

		@Test
		@DisplayName("all initialized fields does not throw")
		void zeroArgumentBuilderValidFields() {
			final ZeroArgument.Builder builder = new ZeroArgument.Builder()
					.with_c_A_0(cA0)
					.with_c_B_m(cBm)
					.with_c_d(cd)
					.with_a_prime(aPrime)
					.with_b_prime(bPrime)
					.with_r_prime(rPrime)
					.with_s_prime(sPrime)
					.with_t_prime(tPrime);

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
		void zeroArgumentBuilderBuildNullFields(final GqElement cA0, final GqElement cBm, final GroupVector<GqElement, GqGroup> cd,
				final GroupVector<ZqElement, ZqGroup> aPrime, final GroupVector<ZqElement, ZqGroup> bPrime, final ZqElement rPrime,
				final ZqElement sPrime, final ZqElement tPrime) {

			final ZeroArgument.Builder builder = new ZeroArgument.Builder()
					.with_c_A_0(cA0)
					.with_c_B_m(cBm)
					.with_c_d(cd)
					.with_a_prime(aPrime)
					.with_b_prime(bPrime)
					.with_r_prime(rPrime)
					.with_s_prime(sPrime)
					.with_t_prime(tPrime);

			assertThrows(NullPointerException.class, builder::build);
		}

		@Test
		@DisplayName("inputs from different GqGroup throws IllegalArgumentException")
		void zeroArgumentBuilderDiffGqGroup() {
			final GqElement otherGroupCA0 = otherGqGroupGenerator.genMember();

			final Builder builder = new Builder()
					.with_c_A_0(otherGroupCA0)
					.with_c_B_m(cBm)
					.with_c_d(cd)
					.with_a_prime(aPrime)
					.with_b_prime(bPrime)
					.with_r_prime(rPrime)
					.with_s_prime(sPrime)
					.with_t_prime(tPrime);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
			assertEquals("cA0, cBm, cd must belong to the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("inputs from different ZqGroup throws IllegalArgumentException")
		void zeroArgumentBuilderDiffZqGroup() {
			final ZqElement otherGroupRPrime = otherZqGroupGenerator.genRandomZqElementMember();

			final Builder builder = new Builder()
					.with_c_A_0(cA0)
					.with_c_B_m(cBm)
					.with_c_d(cd)
					.with_a_prime(aPrime)
					.with_b_prime(bPrime)
					.with_r_prime(otherGroupRPrime)
					.with_s_prime(sPrime)
					.with_t_prime(tPrime);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
			assertEquals("aPrime, bPrime, rPrime, sPrime, tPrime must belong to the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("not compatible GqGroup and ZqGroup throws IllegalArgumentException")
		void zeroArgumentBuilderDiffGqGroupAndZqGroup() {
			final GroupVector<ZqElement, ZqGroup> otherGroupAPrime = otherZqGroupGenerator.genRandomZqElementVector(n);
			final GroupVector<ZqElement, ZqGroup> otherGroupBPrime = otherZqGroupGenerator.genRandomZqElementVector(n);
			final ZqElement otherGroupRPrime = otherZqGroupGenerator.genRandomZqElementMember();
			final ZqElement otherGroupSPrime = otherZqGroupGenerator.genRandomZqElementMember();
			final ZqElement otherGroupTPrime = otherZqGroupGenerator.genRandomZqElementMember();

			final Builder builder = new Builder()
					.with_c_A_0(cA0)
					.with_c_B_m(cBm)
					.with_c_d(cd)
					.with_a_prime(otherGroupAPrime)
					.with_b_prime(otherGroupBPrime)
					.with_r_prime(otherGroupRPrime)
					.with_s_prime(otherGroupSPrime)
					.with_t_prime(otherGroupTPrime);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
			assertEquals("GqGroup and ZqGroup of argument inputs are not compatible.", exception.getMessage());
		}

		@Test
		@DisplayName("aPrime and bPrime of different size throws IllegalArgumentException")
		void zeroArgumentBuilderDiffSizeAPrimeBPrime() {
			final GroupVector<ZqElement, ZqGroup> longerAPrime = zqGroupGenerator.genRandomZqElementVector(n + 1);

			final Builder builder = new Builder()
					.with_c_A_0(cA0)
					.with_c_B_m(cBm)
					.with_c_d(cd)
					.with_a_prime(longerAPrime)
					.with_b_prime(bPrime)
					.with_r_prime(rPrime)
					.with_s_prime(sPrime)
					.with_t_prime(tPrime);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
			assertEquals("The vectors aPrime and bPrime must have the same size.", exception.getMessage());
		}

		@Test
		@DisplayName("built with cd of bad size throws IllegalArgumentException")
		void zeroArgumentBuilderBuildCdBadSize() {
			GroupVector<GqElement, GqGroup> badCd = gqGroupGenerator.genRandomGqElementVector(4);
			final ZeroArgument.Builder builder = new ZeroArgument.Builder()
					.with_c_A_0(cA0)
					.with_c_B_m(cBm)
					.with_c_d(badCd)
					.with_a_prime(aPrime)
					.with_b_prime(bPrime)
					.with_r_prime(rPrime)
					.with_s_prime(sPrime)
					.with_t_prime(tPrime);

			assertThrows(IllegalArgumentException.class, builder::build);
		}
	}
}
