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

import ch.post.it.evoting.cryptoprimitives.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.test.tools.TestGroupSetup;

@DisplayName("A Shuffle Argument")
class ShuffleArgumentTest extends TestGroupSetup {

	private static final int UPPER_BOUND = 10;

	private static int m;
	private static int n;
	private static int l;
	private static TestArgumentGenerator argumentGenerator;

	private static GroupVector<GqElement, GqGroup> cA;
	private static GroupVector<GqElement, GqGroup> cB;
	private static ProductArgument productArgument;
	private static MultiExponentiationArgument multiExponentiationArgument;

	@BeforeAll
	static void setUp() {
		m = secureRandom.nextInt(UPPER_BOUND) + 1;
		n = secureRandom.nextInt(UPPER_BOUND - 1) + 2;
		l = secureRandom.nextInt(UPPER_BOUND) + 1;
		argumentGenerator = new TestArgumentGenerator(gqGroup);

		cA = gqGroupGenerator.genRandomGqElementVector(m);
		cB = gqGroupGenerator.genRandomGqElementVector(m);

		final SingleValueProductArgument singleValueProductArgument = argumentGenerator.genSingleValueProductArgument(n);

		if (m > 1) {
			final GqElement commitmentB = gqGroupGenerator.genMember();
			final HadamardArgument hadamardArgument = argumentGenerator.genHadamardArgument(m, n);

			productArgument = new ProductArgument(commitmentB, hadamardArgument, singleValueProductArgument);
		} else {
			productArgument = new ProductArgument(singleValueProductArgument);
		}

		multiExponentiationArgument = argumentGenerator.genMultiExponentiationArgument(m, n, l);
	}

	@Test
	@DisplayName("hashed with recursiveHash does not throw")
	void hashWithRecursiveHash() {
		final HashService hashService = HashService.getInstance();
		final ShuffleArgument shuffleArgument = new ShuffleArgument.Builder()
				.with_c_A(cA)
				.with_c_B(cB)
				.with_productArgument(productArgument)
				.with_multiExponentiationArgument(multiExponentiationArgument)
				.build();
		assertDoesNotThrow(() -> hashService.recursiveHash(shuffleArgument));
	}

	@Test
	@DisplayName("with valid input returns correct size")
	void getCorrectSize() {
		final ShuffleArgument shuffleArgument = new ShuffleArgument.Builder()
				.with_c_A(cA)
				.with_c_B(cB)
				.with_productArgument(productArgument)
				.with_multiExponentiationArgument(multiExponentiationArgument)
				.build();
		assertEquals(l, shuffleArgument.size());
	}

	@Nested
	@DisplayName("built with")
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	class BuilderTest {

		@Test
		@DisplayName("all initialized fields does not throw")
		void shuffleArgumentBuilderValidFields() {
			final ShuffleArgument.Builder builder = new ShuffleArgument.Builder()
					.with_c_A(cA)
					.with_c_B(cB)
					.with_productArgument(productArgument)
					.with_multiExponentiationArgument(multiExponentiationArgument);

			assertDoesNotThrow(builder::build);
		}

		Stream<Arguments> nullArgumentsProvider() {
			return Stream.of(
					Arguments.of(null, cB, productArgument, multiExponentiationArgument),
					Arguments.of(cA, null, productArgument, multiExponentiationArgument),
					Arguments.of(cA, cB, null, multiExponentiationArgument),
					Arguments.of(cA, cB, productArgument, null)
			);
		}

		@ParameterizedTest
		@MethodSource("nullArgumentsProvider")
		@DisplayName("null fields throws NullPointerException")
		void shuffleArgumentBuilderBuildNullFields(final GroupVector<GqElement, GqGroup> cA, final GroupVector<GqElement, GqGroup> cB,
				final ProductArgument productArgument, final MultiExponentiationArgument multiExponentiationArgument) {

			final ShuffleArgument.Builder builder = new ShuffleArgument.Builder()
					.with_c_A(cA)
					.with_c_B(cB)
					.with_productArgument(productArgument)
					.with_multiExponentiationArgument(multiExponentiationArgument);

			assertThrows(NullPointerException.class, builder::build);
		}

		@Test
		@DisplayName("cA from different group throws IllegalArgumentException")
		void shuffleArgumentBuilderDiffGroupCA() {
			final GroupVector<GqElement, GqGroup> otherGroupCA = otherGqGroupGenerator.genRandomGqElementVector(m);

			final ShuffleArgument.Builder builder = new ShuffleArgument.Builder()
					.with_c_A(otherGroupCA)
					.with_c_B(cB)
					.with_productArgument(productArgument)
					.with_multiExponentiationArgument(multiExponentiationArgument);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
			assertEquals("The commitments cA, cB, the product and the multi exponentiation arguments must belong to the same group.",
					exception.getMessage());
		}

		@Test
		@DisplayName("product argument from different group throws IllegalArgumentException")
		void shuffleArgumentBuilderDiffGroupProduct() {
			final ProductArgument otherGroupProductArgument = new TestArgumentGenerator(otherGqGroup).genProductArgument(m, n);

			final ShuffleArgument.Builder builder = new ShuffleArgument.Builder()
					.with_c_A(cA)
					.with_c_B(cB)
					.with_productArgument(otherGroupProductArgument)
					.with_multiExponentiationArgument(multiExponentiationArgument);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
			assertEquals("The commitments cA, cB, the product and the multi exponentiation arguments must belong to the same group.",
					exception.getMessage());
		}

		@Test
		@DisplayName("multi exponentiation argument from different group throws IllegalArgumentException")
		void shuffleArgumentBuilderDiffGroupMultiExponentiation() {
			final MultiExponentiationArgument otherGroupMultiExponentiationArgument = new TestArgumentGenerator(otherGqGroup)
					.genMultiExponentiationArgument(m, n, l);

			final ShuffleArgument.Builder builder = new ShuffleArgument.Builder()
					.with_c_A(cA)
					.with_c_B(cB)
					.with_productArgument(productArgument)
					.with_multiExponentiationArgument(otherGroupMultiExponentiationArgument);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
			assertEquals("The commitments cA, cB, the product and the multi exponentiation arguments must belong to the same group.",
					exception.getMessage());
		}

		@Test
		@DisplayName("commitment cA having different dimension m than cB and the arguments throws IllegalArgumentException")
		void shuffleArgumentBuilderDiffSizeCA() {
			final GroupVector<GqElement, GqGroup> longerCA = gqGroupGenerator.genRandomGqElementVector(m + 1);

			final ShuffleArgument.Builder builder = new ShuffleArgument.Builder()
					.with_c_A(longerCA)
					.with_c_B(cB)
					.with_productArgument(productArgument)
					.with_multiExponentiationArgument(multiExponentiationArgument);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
			assertEquals("The commitments cA, cB and the product and multi exponentiation arguments must have the same dimension m.",
					exception.getMessage());
		}

		@Test
		@DisplayName("commitments cA, cB having different dimension m than arguments throws IllegalArgumentException")
		void shuffleArgumentBuilderDiffSizeCACBAndArguments() {
			final GroupVector<GqElement, GqGroup> longerCA = gqGroupGenerator.genRandomGqElementVector(m + 1);
			final GroupVector<GqElement, GqGroup> longerCB = gqGroupGenerator.genRandomGqElementVector(m + 1);

			final ShuffleArgument.Builder builder = new ShuffleArgument.Builder()
					.with_c_A(longerCA)
					.with_c_B(longerCB)
					.with_productArgument(productArgument)
					.with_multiExponentiationArgument(multiExponentiationArgument);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
			assertEquals("The commitments cA, cB and the product and multi exponentiation arguments must have the same dimension m.",
					exception.getMessage());
		}

		@Test
		@DisplayName("product and multi exponentiation arguments having different dimension n throws IllegalArgumentException")
		void shuffleArgumentBuilderDiffDimensionNArguments() {
			final MultiExponentiationArgument longerNMultiExponentiationArgument = argumentGenerator.genMultiExponentiationArgument(m, n + 1, l);

			final ShuffleArgument.Builder builder = new ShuffleArgument.Builder()
					.with_c_A(cA)
					.with_c_B(cB)
					.with_productArgument(productArgument)
					.with_multiExponentiationArgument(longerNMultiExponentiationArgument);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
			assertEquals("The product and multi exponentiation arguments must have the same dimension n.",
					exception.getMessage());
		}
	}
}
