/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;

/**
 * Allow to generate at random, based on a gqGroup, the different argument needed in various tests.
 */
class ArgumentGenerator {

	private final GqGroupGenerator gqGroupGenerator;
	private final ZqGroupGenerator zqGroupGenerator;
	private final ElGamalGenerator elGamalGenerator;

	ArgumentGenerator(final GqGroup gqGroup) {
		this.gqGroupGenerator = new GqGroupGenerator(gqGroup);
		this.zqGroupGenerator = new ZqGroupGenerator(ZqGroup.sameOrderAs(gqGroup));
		this.elGamalGenerator = new ElGamalGenerator(gqGroup);
	}

	ZeroArgument genZeroArgument(final int m, final int n) {
		return new ZeroArgument.Builder()
				.withCA0(gqGroupGenerator.genMember())
				.withCBm(gqGroupGenerator.genMember())
				.withCd(gqGroupGenerator.genRandomGqElementVector(2 * m + 1))
				.withAPrime(zqGroupGenerator.genRandomZqElementVector(n))
				.withBPrime(zqGroupGenerator.genRandomZqElementVector(n))
				.withRPrime(zqGroupGenerator.genRandomZqElementMember())
				.withSPrime(zqGroupGenerator.genRandomZqElementMember())
				.withTPrime(zqGroupGenerator.genRandomZqElementMember())
				.build();
	}

	SingleValueProductArgument genSingleValueProductArgument(final int n) {
		return new SingleValueProductArgument.Builder()
				.withCd(gqGroupGenerator.genMember())
				.withCLowerDelta(gqGroupGenerator.genMember())
				.withCUpperDelta(gqGroupGenerator.genMember())
				.withATilde(zqGroupGenerator.genRandomZqElementVector(n))
				.withBTilde(zqGroupGenerator.genRandomZqElementVector(n))
				.withRTilde(zqGroupGenerator.genRandomZqElementMember())
				.withSTilde(zqGroupGenerator.genRandomZqElementMember())
				.build();
	}

	HadamardArgument genHadamardArgument(final int m, final int n) {
		final SameGroupVector<GqElement, GqGroup> commitmentsB = gqGroupGenerator.genRandomGqElementVector(m);
		final ZeroArgument zeroArgument = genZeroArgument(m, n);

		return new HadamardArgument(commitmentsB, zeroArgument);
	}

	ProductArgument genProductArgument(final int m, final int n) {
		final SingleValueProductArgument singleValueProductArgument = genSingleValueProductArgument(n);

		if (m == 1) {
			return new ProductArgument(singleValueProductArgument);
		} else {
			final GqElement commitmentB = gqGroupGenerator.genMember();
			final HadamardArgument hadamardArgument = genHadamardArgument(m, n);

			return new ProductArgument(commitmentB, hadamardArgument, singleValueProductArgument);
		}
	}

	MultiExponentiationArgument genMultiExponentiationArgument(final int m, final int n, final int l) {
		return new MultiExponentiationArgument.Builder()
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

}
