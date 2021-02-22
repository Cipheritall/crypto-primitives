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

	private final ZqGroup group;
	private final RandomService randomService;

	public ZqGroupGenerator(final ZqGroup group) {
		this.group = group;
		this.randomService = new RandomService();
	}

	public ZqElement genRandomZqElementMember() {
		final BigInteger value = randomService.genRandomInteger(this.group.getQ());
		return ZqElement.create(value, this.group);
	}

	/**
	 * Generate a random {@link SameGroupVector} of {@link ZqElement} in this {@code group}.
	 *
	 * @param numElements the number of elements to generate.
	 * @return a vector of {@code numElements} random {@link ZqElement}.
	 */
	public SameGroupVector<ZqElement, ZqGroup> genRandomZqElementVector(final int numElements) {
		return new SameGroupVector<>(generateElementList(numElements, this::genRandomZqElementMember));
	}

	/**
	 * Generate a  {@link SameGroupVector} of {@link ZqElement} in this {@code group}. Populated with {@code element}
	 *
	 * @param numElements the number of elements to generate.
	 * @param element,    value with which the matrix is initialised
	 * @return a vector of {@code numElements} defined {@link ZqElement}.
	 */
	public SameGroupVector<ZqElement, ZqGroup> initializeElementVectorWithElement(final int numElements, ZqElement element) {
		return new SameGroupVector<>(generateElementList(numElements, () -> element));
	}

	/**
	 * Generate a random {@link SameGroupMatrix} of {@link ZqElement} in this {@code group}.
	 *
	 * @param m the matrix' number of lines.
	 * @param n the matrix' number of columns.
	 * @return a m &times; n matrix of random {@link ZqElement}.
	 */
	public SameGroupMatrix<ZqElement, ZqGroup> genRandomZqElementMatrix(final int m, final int n) {
		return SameGroupMatrix.fromRows(generateElementMatrix(m, n, this::genRandomZqElementMember));
	}

	/**
	 * Generate a {@link SameGroupMatrix} of {@link ZqElement} in this {@code group}. Populated with {@code element}
	 *
	 * @param m        the matrix' number of lines.
	 * @param n        the matrix' number of columns.
	 * @param element, value with which the matrix is initialised
	 * @return a m &times; n matrix of defined {@link ZqElement}.
	 */
	public SameGroupMatrix<ZqElement, ZqGroup> initializeMatrixWithElement(final int m, final int n, ZqElement element) {
		return SameGroupMatrix.fromRows(generateElementMatrix(m, n, () -> element));
	}
}
