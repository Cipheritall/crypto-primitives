/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static ch.post.it.evoting.cryptoprimitives.SameGroupVector.toSameGroupVector;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GqGroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;

class SingleValueProductArgumentTest {

	@Test
	void testEquals() {
		GqGroup gqGroup = GqGroupTestData.getGroup();
		ZqGroup zqGroup = ZqGroup.sameOrderAs(gqGroup);

		GqGroupGenerator generator = new GqGroupGenerator(gqGroup);
		RandomService randomService = new RandomService();

		int n = 5;
		final GqElement cd = generator.genNonIdentityMember();
		final GqElement cLowerDelta = generator.genMember();
		final GqElement cUpperDelta = generator.genMember();
		final SameGroupVector<ZqElement, ZqGroup> as = IntStream.range(0, n)
				.mapToObj(i -> randomService.genRandomExponent(zqGroup))
				.collect(toSameGroupVector());
		final SameGroupVector<ZqElement, ZqGroup> bs = IntStream.range(0, n)
				.mapToObj(i -> randomService.genRandomExponent(zqGroup))
				.collect(toSameGroupVector());
		final ZqElement rTilde = randomService.genRandomExponent(zqGroup);
		final ZqElement sTilde = randomService.genRandomExponent(zqGroup);

		// Create singleValueProdArgument 1 == singleValueProdArgument 2 != singleValueProdArgument 3
		SingleValueProductArgument singleValueProdArgument1 = new SingleValueProductArgument.SingleValueProductArgumentBuilder()
				.withCLowerD(cd)
				.withCLowerDelta(cLowerDelta)
				.withCUpperDelta(cUpperDelta)
				.withATilde(as)
				.withBTilde(bs)
				.withRTilde(rTilde)
				.withSTilde(sTilde)
				.build();
		SingleValueProductArgument singleValueProdArgument2 = new SingleValueProductArgument.SingleValueProductArgumentBuilder()
				.withCLowerD(cd)
				.withCLowerDelta(cLowerDelta)
				.withCUpperDelta(cUpperDelta)
				.withATilde(as)
				.withBTilde(bs)
				.withRTilde(rTilde)
				.withSTilde(sTilde)
				.build();
		SingleValueProductArgument singleValueProdArgument3 = new SingleValueProductArgument.SingleValueProductArgumentBuilder()
				.withCLowerD(cd.multiply(cd))
				.withCLowerDelta(cLowerDelta)
				.withCUpperDelta(cUpperDelta)
				.withATilde(as)
				.withBTilde(bs)
				.withRTilde(rTilde)
				.withSTilde(sTilde)
				.build();

		assertEquals(singleValueProdArgument1, singleValueProdArgument1);
		assertEquals(singleValueProdArgument1, singleValueProdArgument2);
		assertNotEquals(singleValueProdArgument1, singleValueProdArgument3);
		assertNotEquals(null, singleValueProdArgument3);
	}
}