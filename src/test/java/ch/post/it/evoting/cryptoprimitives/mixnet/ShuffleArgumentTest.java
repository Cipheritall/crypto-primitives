/*
 * HEADER_LICENSE_OPEN_SOURCE
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

import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;

@DisplayName("A Shuffle Argument")
class ShuffleArgumentTest extends TestGroupSetup {

	private static final int UPPER_BOUND = 10;

	private static int m;
	private static int n;
	private static int l;
	private static ArgumentGenerator argumentGenerator;

	private static SameGroupVector<GqElement, GqGroup> cA;
	private static SameGroupVector<GqElement, GqGroup> cB;
	private static ProductArgument productArgument;
	private static MultiExponentiationArgument multiExponentiationArgument;

	@BeforeAll
	static void setUp() {
		m = secureRandom.nextInt(UPPER_BOUND) + 1;
		n = secureRandom.nextInt(UPPER_BOUND - 1) + 2;
		l = secureRandom.nextInt(UPPER_BOUND) + 1;
		argumentGenerator = new ArgumentGenerator(gqGroup);

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

	@Nested
	@DisplayName("built with")
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	class BuilderTest {

		@Test
		@DisplayName("all initialized fields does not throw")
		void shuffleArgumentBuilderValidFields() {
			final ShuffleArgument.Builder builder = new ShuffleArgument.Builder()
					.withCA(cA)
					.withCB(cB)
					.withProductArgument(productArgument)
					.withMultiExponentiationArgument(multiExponentiationArgument);

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
		void shuffleArgumentBuilderBuildNullFields(final SameGroupVector<GqElement, GqGroup> cA, final SameGroupVector<GqElement, GqGroup> cB,
				final ProductArgument productArgument, final MultiExponentiationArgument multiExponentiationArgument) {

			final ShuffleArgument.Builder builder = new ShuffleArgument.Builder()
					.withCA(cA)
					.withCB(cB)
					.withProductArgument(productArgument)
					.withMultiExponentiationArgument(multiExponentiationArgument);

			assertThrows(NullPointerException.class, builder::build);
		}

		@Test
		@DisplayName("cA from different group throws IllegalArgumentException")
		void shuffleArgumentBuilderDiffGroupCA() {
			final SameGroupVector<GqElement, GqGroup> otherGroupCA = otherGqGroupGenerator.genRandomGqElementVector(m);

			final ShuffleArgument.Builder builder = new ShuffleArgument.Builder()
					.withCA(otherGroupCA)
					.withCB(cB)
					.withProductArgument(productArgument)
					.withMultiExponentiationArgument(multiExponentiationArgument);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
			assertEquals("The commitments cA, cB, the product and the multi exponentiation arguments must belong to the same group.",
					exception.getMessage());
		}

		@Test
		@DisplayName("product argument from different group throws IllegalArgumentException")
		void shuffleArgumentBuilderDiffGroupProduct() {
			final ProductArgument otherGroupProductArgument = new ArgumentGenerator(otherGqGroup).genProductArgument(m, n);

			final ShuffleArgument.Builder builder = new ShuffleArgument.Builder()
					.withCA(cA)
					.withCB(cB)
					.withProductArgument(otherGroupProductArgument)
					.withMultiExponentiationArgument(multiExponentiationArgument);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
			assertEquals("The commitments cA, cB, the product and the multi exponentiation arguments must belong to the same group.",
					exception.getMessage());
		}

		@Test
		@DisplayName("multi exponentiation argument from different group throws IllegalArgumentException")
		void shuffleArgumentBuilderDiffGroupMultiExponentiation() {
			final MultiExponentiationArgument otherGroupMultiExponentiationArgument = new ArgumentGenerator(otherGqGroup)
					.genMultiExponentiationArgument(m, n, l);

			final ShuffleArgument.Builder builder = new ShuffleArgument.Builder()
					.withCA(cA)
					.withCB(cB)
					.withProductArgument(productArgument)
					.withMultiExponentiationArgument(otherGroupMultiExponentiationArgument);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
			assertEquals("The commitments cA, cB, the product and the multi exponentiation arguments must belong to the same group.",
					exception.getMessage());
		}

		@Test
		@DisplayName("commitment cA having different dimension m than cB and the arguments throws IllegalArgumentException")
		void shuffleArgumentBuilderDiffSizeCA() {
			final SameGroupVector<GqElement, GqGroup> longerCA = gqGroupGenerator.genRandomGqElementVector(m + 1);

			final ShuffleArgument.Builder builder = new ShuffleArgument.Builder()
					.withCA(longerCA)
					.withCB(cB)
					.withProductArgument(productArgument)
					.withMultiExponentiationArgument(multiExponentiationArgument);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
			assertEquals("The commitments cA, cB and the product and multi exponentiation arguments must have the same dimension m.",
					exception.getMessage());
		}

		@Test
		@DisplayName("commitments cA, cB having different dimension m than arguments throws IllegalArgumentException")
		void shuffleArgumentBuilderDiffSizeCACBAndArguments() {
			final SameGroupVector<GqElement, GqGroup> longerCA = gqGroupGenerator.genRandomGqElementVector(m + 1);
			final SameGroupVector<GqElement, GqGroup> longerCB = gqGroupGenerator.genRandomGqElementVector(m + 1);

			final ShuffleArgument.Builder builder = new ShuffleArgument.Builder()
					.withCA(longerCA)
					.withCB(longerCB)
					.withProductArgument(productArgument)
					.withMultiExponentiationArgument(multiExponentiationArgument);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
			assertEquals("The commitments cA, cB and the product and multi exponentiation arguments must have the same dimension m.",
					exception.getMessage());
		}

		@Test
		@DisplayName("product and multi exponentiation arguments having different dimension n throws IllegalArgumentException")
		void shuffleArgumentBuilderDiffDimensionNArguments() {
			final MultiExponentiationArgument longerNMultiExponentiationArgument = argumentGenerator.genMultiExponentiationArgument(m, n + 1, l);

			final ShuffleArgument.Builder builder = new ShuffleArgument.Builder()
					.withCA(cA)
					.withCB(cB)
					.withProductArgument(productArgument)
					.withMultiExponentiationArgument(longerNMultiExponentiationArgument);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
			assertEquals("The product and multi exponentiation arguments must have the same dimension n.",
					exception.getMessage());
		}
	}
}
