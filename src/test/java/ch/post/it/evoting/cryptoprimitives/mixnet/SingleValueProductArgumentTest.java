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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
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
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

@DisplayName("A SingleValueProductArgument")
class SingleValueProductArgumentTest extends TestGroupSetup {

	private static final int UPPER_BOUND = 10;

	private static int n;

	private static GqElement cd;
	private static GqElement cLowerDelta;
	private static GqElement cUpperDelta;
	private static SameGroupVector<ZqElement, ZqGroup> aTilde;
	private static SameGroupVector<ZqElement, ZqGroup> bTilde;
	private static ZqElement rTilde;
	private static ZqElement sTilde;

	@BeforeAll
	static void setUpAll() {
		n = secureRandom.nextInt(UPPER_BOUND) + 1;
		final SingleValueProductArgument singleValueProductArgument = new ArgumentGenerator(gqGroup).genSingleValueProductArgument(n);

		cd = singleValueProductArgument.getCd();
		cLowerDelta = singleValueProductArgument.getCLowerDelta();
		cUpperDelta = singleValueProductArgument.getCUpperDelta();
		aTilde = singleValueProductArgument.getATilde();
		bTilde = singleValueProductArgument.getBTilde();
		rTilde = singleValueProductArgument.getRTilde();
		sTilde = singleValueProductArgument.getSTilde();
	}

	@Test
	void testEquals() {
		// Create singleValueProdArgument 1 == singleValueProdArgument 2 != singleValueProdArgument 3
		SingleValueProductArgument singleValueProdArgument1 = new SingleValueProductArgument.Builder()
				.withCd(cd)
				.withCLowerDelta(cLowerDelta)
				.withCUpperDelta(cUpperDelta)
				.withATilde(aTilde)
				.withBTilde(bTilde)
				.withRTilde(rTilde)
				.withSTilde(sTilde)
				.build();

		SingleValueProductArgument singleValueProdArgument2 = new SingleValueProductArgument.Builder()
				.withCd(cd)
				.withCLowerDelta(cLowerDelta)
				.withCUpperDelta(cUpperDelta)
				.withATilde(aTilde)
				.withBTilde(bTilde)
				.withRTilde(rTilde)
				.withSTilde(sTilde)
				.build();

		SingleValueProductArgument singleValueProdArgument3 = new SingleValueProductArgument.Builder()
				.withCd(cd.multiply(cd))
				.withCLowerDelta(cLowerDelta)
				.withCUpperDelta(cUpperDelta)
				.withATilde(aTilde)
				.withBTilde(bTilde)
				.withRTilde(rTilde)
				.withSTilde(sTilde)
				.build();

		assertEquals(singleValueProdArgument1, singleValueProdArgument1);
		assertEquals(singleValueProdArgument1, singleValueProdArgument2);
		assertNotEquals(singleValueProdArgument1, singleValueProdArgument3);
		assertNotEquals(null, singleValueProdArgument3);
	}

	@Nested
	@DisplayName("built with")
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	class BuilderTest {

		@Test
		@DisplayName("all initialized fields does not throw")
		void singleValueProductBuilderValidFields() {
			final SingleValueProductArgument.Builder builder = new SingleValueProductArgument.Builder()
					.withCd(cd)
					.withCLowerDelta(cLowerDelta)
					.withCUpperDelta(cUpperDelta)
					.withATilde(aTilde)
					.withBTilde(bTilde)
					.withRTilde(rTilde)
					.withSTilde(sTilde);

			assertDoesNotThrow(builder::build);
		}

		Stream<Arguments> nullArgumentsProvider() {
			return Stream.of(
					Arguments.of(null, cLowerDelta, cUpperDelta, aTilde, bTilde, rTilde, sTilde),
					Arguments.of(cd, null, cUpperDelta, aTilde, bTilde, rTilde, sTilde),
					Arguments.of(cd, cLowerDelta, null, aTilde, bTilde, rTilde, sTilde),
					Arguments.of(cd, cLowerDelta, cUpperDelta, null, bTilde, rTilde, sTilde),
					Arguments.of(cd, cLowerDelta, cUpperDelta, aTilde, null, rTilde, sTilde),
					Arguments.of(cd, cLowerDelta, cUpperDelta, aTilde, bTilde, null, sTilde),
					Arguments.of(cd, cLowerDelta, cUpperDelta, aTilde, bTilde, rTilde, null)
			);
		}

		@ParameterizedTest
		@MethodSource("nullArgumentsProvider")
		@DisplayName("null fields throws NullPointerException")
		void singleValueProductBuilderBuildNullFields(final GqElement cd, final GqElement cLowerDelta, final GqElement cUpperDelta,
				final SameGroupVector<ZqElement, ZqGroup> aTilde, final SameGroupVector<ZqElement, ZqGroup> bTilde, final ZqElement rTilde,
				final ZqElement sTilde) {

			final SingleValueProductArgument.Builder builder = new SingleValueProductArgument.Builder()
					.withCd(cd)
					.withCLowerDelta(cLowerDelta)
					.withCUpperDelta(cUpperDelta)
					.withATilde(aTilde)
					.withBTilde(bTilde)
					.withRTilde(rTilde)
					.withSTilde(sTilde);

			assertThrows(NullPointerException.class, builder::build);
		}

		@Test
		@DisplayName("inputs from different GqGroup throws IllegalArgumentException")
		void singleValueProductBuilderDiffGqGroup() {
			final GqElement otherGroupCd = otherGqGroupGenerator.genNonIdentityMember();

			final SingleValueProductArgument.Builder builder = new SingleValueProductArgument.Builder()
					.withCd(otherGroupCd)
					.withCLowerDelta(cLowerDelta)
					.withCUpperDelta(cUpperDelta)
					.withATilde(aTilde)
					.withBTilde(bTilde)
					.withRTilde(rTilde)
					.withSTilde(sTilde);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
			assertEquals("cd, cLowerDelta, cUpperDelta must belong to the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("inputs from different ZqGroup throws IllegalArgumentException")
		void singleValueProductBuilderDiffZqGroup() {
			final ZqElement otherGroupRTilde = otherZqGroupGenerator.genRandomZqElementMember();

			final SingleValueProductArgument.Builder builder = new SingleValueProductArgument.Builder()
					.withCd(cd)
					.withCLowerDelta(cLowerDelta)
					.withCUpperDelta(cUpperDelta)
					.withATilde(aTilde)
					.withBTilde(bTilde)
					.withRTilde(otherGroupRTilde)
					.withSTilde(sTilde);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
			assertEquals("aTilde, bTilde, rTilde, sTilde must belong to the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("not compatible GqGroup and ZqGroup throws IllegalArgumentException")
		void singleValueProductBuilderDiffGqGroupAndZqGroup() {
			final SameGroupVector<ZqElement, ZqGroup> otherGroupATilde = otherZqGroupGenerator.genRandomZqElementVector(n);
			final SameGroupVector<ZqElement, ZqGroup> otherGroupBTilde = otherZqGroupGenerator.genRandomZqElementVector(n);
			final ZqElement otherGroupRTilde = otherZqGroupGenerator.genRandomZqElementMember();
			final ZqElement otherGroupSTilde = otherZqGroupGenerator.genRandomZqElementMember();

			final SingleValueProductArgument.Builder builder = new SingleValueProductArgument.Builder()
					.withCd(cd)
					.withCLowerDelta(cLowerDelta)
					.withCUpperDelta(cUpperDelta)
					.withATilde(otherGroupATilde)
					.withBTilde(otherGroupBTilde)
					.withRTilde(otherGroupRTilde)
					.withSTilde(otherGroupSTilde);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
			assertEquals("GqGroup and ZqGroup of argument inputs are not compatible.", exception.getMessage());
		}

		@Test
		@DisplayName("aTilde and bTilde of different size throws IllegalArgumentException")
		void singleValueProductBuilderDiffSizeATildeBTilde() {
			final SameGroupVector<ZqElement, ZqGroup> longerATilde = zqGroupGenerator.genRandomZqElementVector(n + 1);

			final SingleValueProductArgument.Builder builder = new SingleValueProductArgument.Builder()
					.withCd(cd)
					.withCLowerDelta(cLowerDelta)
					.withCUpperDelta(cUpperDelta)
					.withATilde(longerATilde)
					.withBTilde(bTilde)
					.withRTilde(rTilde)
					.withSTilde(sTilde);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
			assertEquals("The vectors aTilde and bTilde must have the same size.", exception.getMessage());
		}

		@Test
		@DisplayName("aTilde and bTilde of size not greater than or equal to 2 throws IllegalArgumentException")
		void singleValueProductBuilderWrongSizeATildeBTilde() {
			final SameGroupVector<ZqElement, ZqGroup> shorterATilde = zqGroupGenerator.genRandomZqElementVector(1);
			final SameGroupVector<ZqElement, ZqGroup> shorterBTilde = zqGroupGenerator.genRandomZqElementVector(1);

			final SingleValueProductArgument.Builder builder = new SingleValueProductArgument.Builder()
					.withCd(cd)
					.withCLowerDelta(cLowerDelta)
					.withCUpperDelta(cUpperDelta)
					.withATilde(shorterATilde)
					.withBTilde(shorterBTilde)
					.withRTilde(rTilde)
					.withSTilde(sTilde);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
			assertEquals("The size of vectors aTilde and bTilde must be greater than or equal to 2.", exception.getMessage());
		}
	}
}
