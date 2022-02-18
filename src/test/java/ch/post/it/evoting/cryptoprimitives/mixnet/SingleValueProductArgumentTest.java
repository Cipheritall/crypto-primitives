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

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.TestGroupSetup;

@DisplayName("A SingleValueProductArgument")
class SingleValueProductArgumentTest extends TestGroupSetup {

	private static final int UPPER_BOUND = 10;

	private static int n;

	private static GqElement cd;
	private static GqElement cLowerDelta;
	private static GqElement cUpperDelta;
	private static GroupVector<ZqElement, ZqGroup> aTilde;
	private static GroupVector<ZqElement, ZqGroup> bTilde;
	private static ZqElement rTilde;
	private static ZqElement sTilde;

	@BeforeAll
	static void setUpAll() {
		n = secureRandom.nextInt(UPPER_BOUND) + 2;
		final SingleValueProductArgument singleValueProductArgument = new TestArgumentGenerator(gqGroup).genSingleValueProductArgument(n);

		cd = singleValueProductArgument.get_c_d();
		cLowerDelta = singleValueProductArgument.get_c_delta();
		cUpperDelta = singleValueProductArgument.get_c_Delta();
		aTilde = singleValueProductArgument.get_a_tilde();
		bTilde = singleValueProductArgument.get_b_tilde();
		rTilde = singleValueProductArgument.get_r_tilde();
		sTilde = singleValueProductArgument.get_s_tilde();
	}

	@Test
	void testEquals() {
		// Create singleValueProdArgument 1 == singleValueProdArgument 2 != singleValueProdArgument 3
		SingleValueProductArgument singleValueProdArgument1 = new SingleValueProductArgument.Builder()
				.with_c_d(cd)
				.with_c_delta(cLowerDelta)
				.with_c_Delta(cUpperDelta)
				.with_a_tilde(aTilde)
				.with_b_tilde(bTilde)
				.with_r_tilde(rTilde)
				.with_s_tilde(sTilde)
				.build();

		SingleValueProductArgument singleValueProdArgument2 = new SingleValueProductArgument.Builder()
				.with_c_d(cd)
				.with_c_delta(cLowerDelta)
				.with_c_Delta(cUpperDelta)
				.with_a_tilde(aTilde)
				.with_b_tilde(bTilde)
				.with_r_tilde(rTilde)
				.with_s_tilde(sTilde)
				.build();

		SingleValueProductArgument singleValueProdArgument3 = new SingleValueProductArgument.Builder()
				.with_c_d(gqGroupGenerator.otherElement(cd))
				.with_c_delta(cLowerDelta)
				.with_c_Delta(cUpperDelta)
				.with_a_tilde(aTilde)
				.with_b_tilde(bTilde)
				.with_r_tilde(rTilde)
				.with_s_tilde(sTilde)
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
					.with_c_d(cd)
					.with_c_delta(cLowerDelta)
					.with_c_Delta(cUpperDelta)
					.with_a_tilde(aTilde)
					.with_b_tilde(bTilde)
					.with_r_tilde(rTilde)
					.with_s_tilde(sTilde);

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
				final GroupVector<ZqElement, ZqGroup> aTilde, final GroupVector<ZqElement, ZqGroup> bTilde, final ZqElement rTilde,
				final ZqElement sTilde) {

			final SingleValueProductArgument.Builder builder = new SingleValueProductArgument.Builder()
					.with_c_d(cd)
					.with_c_delta(cLowerDelta)
					.with_c_Delta(cUpperDelta)
					.with_a_tilde(aTilde)
					.with_b_tilde(bTilde)
					.with_r_tilde(rTilde)
					.with_s_tilde(sTilde);

			assertThrows(NullPointerException.class, builder::build);
		}

		@Test
		@DisplayName("inputs from different GqGroup throws IllegalArgumentException")
		void singleValueProductBuilderDiffGqGroup() {
			final GqElement otherGroupCd = otherGqGroupGenerator.genNonIdentityMember();

			final SingleValueProductArgument.Builder builder = new SingleValueProductArgument.Builder()
					.with_c_d(otherGroupCd)
					.with_c_delta(cLowerDelta)
					.with_c_Delta(cUpperDelta)
					.with_a_tilde(aTilde)
					.with_b_tilde(bTilde)
					.with_r_tilde(rTilde)
					.with_s_tilde(sTilde);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
			assertEquals("cd, cLowerDelta, cUpperDelta must belong to the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("inputs from different ZqGroup throws IllegalArgumentException")
		void singleValueProductBuilderDiffZqGroup() {
			final ZqElement otherGroupRTilde = otherZqGroupGenerator.genRandomZqElementMember();

			final SingleValueProductArgument.Builder builder = new SingleValueProductArgument.Builder()
					.with_c_d(cd)
					.with_c_delta(cLowerDelta)
					.with_c_Delta(cUpperDelta)
					.with_a_tilde(aTilde)
					.with_b_tilde(bTilde)
					.with_r_tilde(otherGroupRTilde)
					.with_s_tilde(sTilde);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
			assertEquals("aTilde, bTilde, rTilde, sTilde must belong to the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("not compatible GqGroup and ZqGroup throws IllegalArgumentException")
		void singleValueProductBuilderDiffGqGroupAndZqGroup() {
			final GroupVector<ZqElement, ZqGroup> otherGroupATilde = otherZqGroupGenerator.genRandomZqElementVector(n);
			final GroupVector<ZqElement, ZqGroup> otherGroupBTilde = otherZqGroupGenerator.genRandomZqElementVector(n);
			final ZqElement otherGroupRTilde = otherZqGroupGenerator.genRandomZqElementMember();
			final ZqElement otherGroupSTilde = otherZqGroupGenerator.genRandomZqElementMember();

			final SingleValueProductArgument.Builder builder = new SingleValueProductArgument.Builder()
					.with_c_d(cd)
					.with_c_delta(cLowerDelta)
					.with_c_Delta(cUpperDelta)
					.with_a_tilde(otherGroupATilde)
					.with_b_tilde(otherGroupBTilde)
					.with_r_tilde(otherGroupRTilde)
					.with_s_tilde(otherGroupSTilde);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
			assertEquals("GqGroup and ZqGroup of argument inputs are not compatible.", exception.getMessage());
		}

		@Test
		@DisplayName("aTilde and bTilde of different size throws IllegalArgumentException")
		void singleValueProductBuilderDiffSizeATildeBTilde() {
			final GroupVector<ZqElement, ZqGroup> longerATilde = zqGroupGenerator.genRandomZqElementVector(n + 1);

			final SingleValueProductArgument.Builder builder = new SingleValueProductArgument.Builder()
					.with_c_d(cd)
					.with_c_delta(cLowerDelta)
					.with_c_Delta(cUpperDelta)
					.with_a_tilde(longerATilde)
					.with_b_tilde(bTilde)
					.with_r_tilde(rTilde)
					.with_s_tilde(sTilde);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
			assertEquals("The vectors aTilde and bTilde must have the same size.", exception.getMessage());
		}

		@Test
		@DisplayName("aTilde and bTilde of size not greater than or equal to 2 throws IllegalArgumentException")
		void singleValueProductBuilderWrongSizeATildeBTilde() {
			final GroupVector<ZqElement, ZqGroup> shorterATilde = zqGroupGenerator.genRandomZqElementVector(1);
			final GroupVector<ZqElement, ZqGroup> shorterBTilde = zqGroupGenerator.genRandomZqElementVector(1);

			final SingleValueProductArgument.Builder builder = new SingleValueProductArgument.Builder()
					.with_c_d(cd)
					.with_c_delta(cLowerDelta)
					.with_c_Delta(cUpperDelta)
					.with_a_tilde(shorterATilde)
					.with_b_tilde(shorterBTilde)
					.with_r_tilde(rTilde)
					.with_s_tilde(sTilde);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
			assertEquals("The size of vectors aTilde and bTilde must be greater than or equal to 2.", exception.getMessage());
		}
	}
}
