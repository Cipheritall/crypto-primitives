/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.test.tools.generator;

import static ch.post.it.evoting.cryptoprimitives.test.tools.generator.HasGroupElementGenerator.generateElementList;
import static ch.post.it.evoting.cryptoprimitives.test.tools.generator.HasGroupElementGenerator.generateElementMatrix;

import java.math.BigInteger;

import ch.post.it.evoting.cryptoprimitives.SameGroupMatrix;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;

public class ZqGroupGenerator {

	private static final BigInteger UPPER_BOUND_Q = BigInteger.valueOf(100);

	private final ZqGroup group;
	private final RandomService randomService;

	public ZqGroupGenerator(final ZqGroup group) {
		this.group = group;
		this.randomService = new RandomService();
	}

	public ZqElement genZqElementMember() {
		final BigInteger value = randomService.genRandomInteger(this.group.getQ());
		return ZqElement.create(value, this.group);
	}

	public ZqGroup otherGroup() {
		BigInteger q;
		do {
			q = this.randomService.genRandomIntegerWithinBounds(BigInteger.valueOf(2), UPPER_BOUND_Q);
		} while (q.equals(group.getQ()));
		return new ZqGroup(q);
	}

	/**
	 * Generate a random {@link SameGroupVector} of {@link ZqElement} in this {@code group}.
	 *
	 * @param numElements the number of elements to generate.
	 * @return a vector of {@code numElements} random {@link ZqElement}.
	 */
	public SameGroupVector<ZqElement, ZqGroup> generateRandomZqElementVector(final int numElements) {
		return new SameGroupVector<>(generateElementList(numElements, this::genZqElementMember));
	}

	/**
	 * Generate a random {@link SameGroupMatrix} of {@link ZqElement} in this {@code group}.
	 *
	 * @param m the matrix' number of lines.
	 * @param n the matrix' number of columns.
	 * @return a m &times; n matrix of random {@link ZqElement}.
	 */
	public SameGroupMatrix<ZqElement, ZqGroup> generateRandomZqElementMatrix(final int m, final int n) {
		return SameGroupMatrix.fromRows(generateElementMatrix(m, n, this::genZqElementMember));
	}
}
