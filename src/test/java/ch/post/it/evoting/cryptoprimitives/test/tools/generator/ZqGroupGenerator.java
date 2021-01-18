/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.test.tools.generator;

import java.math.BigInteger;

import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;

public class ZqGroupGenerator {
	private static final BigInteger UPPER_BOUND_Q = BigInteger.valueOf(100);

	private final ZqGroup group;
	private final RandomService randomService;

	public ZqGroupGenerator(ZqGroup group) {
		this.group = group;
		this.randomService = new RandomService();
	}

	public ZqElement genZqElementMember() {
		BigInteger value = randomService.genRandomInteger(this.group.getQ());
		return ZqElement.create(value, this.group);
	}

	public ZqGroup otherGroup() {
		BigInteger q;
		do {
			q = this.randomService.genRandomInteger(UPPER_BOUND_Q);
		} while (q.equals(group.getQ()));
		return new ZqGroup(q);
	}
}
