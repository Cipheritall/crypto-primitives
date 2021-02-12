/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;

class MultiExponentiationArgumentTest extends TestGroupSetup {

	private static final int DIMENSIONS_BOUND = 10;
	private static GqElement cA0;
	private static SameGroupVector<GqElement, GqGroup> cbVector;
	private static SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> EVector;
	private static SameGroupVector<ZqElement, ZqGroup> aVector;
	private static ZqElement r;
	private static ZqElement b;
	private static ZqElement s;
	private static ZqElement tau;

	@BeforeAll
	static void setUp() {
		int n = secureRandom.nextInt(DIMENSIONS_BOUND) + 1;
		int m = secureRandom.nextInt(DIMENSIONS_BOUND) + 1;
		int l = secureRandom.nextInt(DIMENSIONS_BOUND) + 1;
		cA0 = gqGroupGenerator.genMember();
		cbVector = gqGroupGenerator.genRandomGqElementVector(2 * m);
		ElGamalGenerator elGamalGenerator = new ElGamalGenerator(gqGroup);
		EVector = elGamalGenerator.genRandomCiphertextVector(2 * m, l);
		aVector = zqGroupGenerator.genRandomZqElementVector(n);
		r = zqGroupGenerator.genRandomZqElementMember();
		b = zqGroupGenerator.genRandomZqElementMember();
		s = zqGroupGenerator.genRandomZqElementMember();
		tau = zqGroupGenerator.genRandomZqElementMember();
	}

	@Test
	void builtWithAllSetDoesNotThrow() {
		MultiExponentiationArgument.Builder builder = new MultiExponentiationArgument.Builder();
		assertDoesNotThrow(() -> builder
				.withcA0(cA0)
				.withcbVector(cbVector)
				.withEVector(EVector)
				.withaVector(aVector)
				.withr(r)
				.withb(b)
				.withs(s)
				.withtau(tau)
				.build()
		);
	}

	static Stream<Arguments> nullArgumentsProvider() {
		return Stream.of(
				Arguments.of(null, cbVector, EVector, aVector, r, b, s, tau),
				Arguments.of(cA0, null, EVector, aVector, r, b, s, tau),
				Arguments.of(cA0, cbVector, null, aVector, r, b, s, tau),
				Arguments.of(cA0, cbVector, EVector, null, r, b, s, tau),
				Arguments.of(cA0, cbVector, EVector, aVector, null, b, s, tau),
				Arguments.of(cA0, cbVector, EVector, aVector, r, null, s, tau),
				Arguments.of(cA0, cbVector, EVector, aVector, r, b, null, tau),
				Arguments.of(cA0, cbVector, EVector, aVector, r, b, s, null)
		);
	}

	@ParameterizedTest
	@MethodSource("nullArgumentsProvider")
	void zeroArgumentBuilderBuildNullFields(GqElement cA0, SameGroupVector<GqElement, GqGroup> cbVector,
			SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> EVector, SameGroupVector<ZqElement, ZqGroup> aVector, ZqElement r, ZqElement b,
			ZqElement s, ZqElement tau) {

		MultiExponentiationArgument.Builder builder = new MultiExponentiationArgument.Builder();
		builder.withcA0(cA0)
				.withcbVector(cbVector)
				.withEVector(EVector)
				.withaVector(aVector)
				.withr(r)
				.withb(b)
				.withs(s)
				.withtau(tau);
		assertThrows(NullPointerException.class, builder::build);
	}
}