package ch.post.it.evoting.cryptoprimitives.mixnet;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;

class ShuffleArgumentTest extends TestGroupSetup {

	private static final int NUM_ELEMENTS = 10;

	private static SameGroupVector<GqElement, GqGroup> cA;
	private static SameGroupVector<GqElement, GqGroup> cB;
	private static ProductArgument productArgument;
	private static MultiExponentiationArgument multiExponentiationArgument;

	@BeforeAll
	static void setUp() {
		final int m = secureRandom.nextInt(NUM_ELEMENTS) + 1;
		final int n = secureRandom.nextInt(NUM_ELEMENTS) + 1;
		final int l = secureRandom.nextInt(NUM_ELEMENTS) + 1;
		final ElGamalGenerator elGamalGenerator = new ElGamalGenerator(gqGroup);

		cA = gqGroupGenerator.genRandomGqElementVector(m);
		cB = gqGroupGenerator.genRandomGqElementVector(m);

		final SingleValueProductArgument singleValueProductArgument = new SingleValueProductArgument.Builder()
				.withCd(gqGroupGenerator.genMember())
				.withCLowerDelta(gqGroupGenerator.genMember())
				.withCUpperDelta(gqGroupGenerator.genMember())
				.withATilde(zqGroupGenerator.genRandomZqElementVector(n))
				.withBTilde(zqGroupGenerator.genRandomZqElementVector(n))
				.withRTilde(zqGroupGenerator.genRandomZqElementMember())
				.withSTilde(zqGroupGenerator.genRandomZqElementMember())
				.build();
		productArgument = new ProductArgument(singleValueProductArgument);

		multiExponentiationArgument = new MultiExponentiationArgument.Builder()
				.withcA0(gqGroupGenerator.genMember())
				.withcBVector(gqGroupGenerator.genRandomGqElementVector(2 * m))
				.withEVector(elGamalGenerator.genRandomCiphertextVector(2 * m, l))
				.withaVector(zqGroupGenerator.genRandomZqElementVector(n))
				.withr(zqGroupGenerator.genRandomZqElementMember())
				.withb(zqGroupGenerator.genRandomZqElementMember())
				.withs(zqGroupGenerator.genRandomZqElementMember())
				.withtau(zqGroupGenerator.genRandomZqElementMember())
				.build();
	}

	@Test
	@DisplayName("built with all initialized fields does not throw")
	void shuffleArgumentBuilderValidFields() {
		final ShuffleArgument.Builder builder = new ShuffleArgument.Builder()
				.withCA(cA)
				.withCB(cB)
				.withProductArgument(productArgument)
				.withMultiExponentiationArgument(multiExponentiationArgument);

		assertDoesNotThrow(builder::build);
	}

	static Stream<Arguments> nullArgumentsProvider() {
		return Stream.of(
				Arguments.of(null, cB, productArgument, multiExponentiationArgument),
				Arguments.of(cA, null, productArgument, multiExponentiationArgument),
				Arguments.of(cA, cB, null, multiExponentiationArgument),
				Arguments.of(cA, cB, productArgument, null)
		);
	}

	@ParameterizedTest
	@MethodSource("nullArgumentsProvider")
	@DisplayName("built with null fields throws NullPointerException")
	void zeroArgumentBuilderBuildNullFields(final SameGroupVector<GqElement, GqGroup> cA, final SameGroupVector<GqElement, GqGroup> cB,
			final ProductArgument productArgument, final MultiExponentiationArgument multiExponentiationArgument) {

		final ShuffleArgument.Builder builder = new ShuffleArgument.Builder()
				.withCA(cA)
				.withCB(cB)
				.withProductArgument(productArgument)
				.withMultiExponentiationArgument(multiExponentiationArgument);

		assertThrows(NullPointerException.class, builder::build);
	}
}
