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
package ch.post.it.evoting.cryptoprimitives.test.tools.generator;

import static ch.post.it.evoting.cryptoprimitives.test.tools.generator.GroupVectorElementGenerator.generateElementList;
import static ch.post.it.evoting.cryptoprimitives.test.tools.generator.GroupVectorElementGenerator.generateElementMatrix;
import static com.google.common.base.Preconditions.checkArgument;

import java.math.BigInteger;

import ch.post.it.evoting.cryptoprimitives.math.GroupMatrix;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

public class ZqGroupGenerator {

	private final ZqGroup group;
	private final RandomService randomService;

	public ZqGroupGenerator(final ZqGroup group) {
		this.group = group;
		this.randomService = new RandomService();
	}

	/**
	 * Generates a random {@link ZqElement} in this {@code group}.
	 *
	 * @return a random {@link ZqElement}.
	 */
	public ZqElement genRandomZqElementMember() {
		final BigInteger value = randomService.genRandomInteger(this.group.getQ());
		return ZqElement.create(value, this.group);
	}

	/**
	 * Generates a random {@link ZqElement} in this {@code group} different from another {@link ZqElement}.
	 *
	 * @param element the other {@link ZqElement}.
	 * @return a random {@link ZqElement} different from the other {@link ZqElement}.
	 */
	public ZqElement genOtherElement(final ZqElement element) {
		return Generators.genWhile(this::genRandomZqElementMember, element::equals);
	}

	/**
	 * Generate a random {@link GroupVector} of {@link ZqElement} in this {@code group}.
	 *
	 * @param numElements the number of elements to generate.
	 * @return a vector of {@code numElements} random {@link ZqElement}.
	 */
	public GroupVector<ZqElement, ZqGroup> genRandomZqElementVector(final int numElements) {
		return GroupVector.from(generateElementList(numElements, this::genRandomZqElementMember));
	}

	/**
	 * Generates a random {@link GroupVector} of {@link ZqElement} in this {@code group} different from another {@link GroupVector}.
	 *
	 * @param vector      the other {@link GroupVector}.
	 * @param numElements the number of elements to generate.
	 * @return a vector of {@code numElements} random {@link ZqElement} different from the other {@link GroupVector}.
	 */
	public GroupVector<ZqElement, ZqGroup> genOtherVector(final GroupVector<ZqElement, ZqGroup> vector, final int numElements) {
		return Generators.genWhile(() -> genRandomZqElementVector(numElements), vector::equals);
	}

	/**
	 * Generate a  {@link GroupVector} of {@link ZqElement} in this {@code group}. Populated with {@code element}
	 *
	 * @param numElements the number of elements to generate.
	 * @param element,    value with which the matrix is initialised
	 * @return a vector of {@code numElements} defined {@link ZqElement}.
	 */
	public GroupVector<ZqElement, ZqGroup> initializeElementVectorWithElement(final int numElements, final ZqElement element) {
		return GroupVector.from(generateElementList(numElements, () -> element));
	}

	/**
	 * Generate a random {@link GroupMatrix} of {@link ZqElement} in this {@code group}.
	 *
	 * @param n the matrix' number of lines, greater than 0.
	 * @param m the matrix' number of columns, greater than 0.
	 * @return a n &times; m matrix of random {@link ZqElement}.
	 */
	public GroupMatrix<ZqElement, ZqGroup> genRandomZqElementMatrix(final int m, final int n) {
		checkArgument(n > 0);
		checkArgument(m > 0);
		return GroupMatrix.fromRows(generateElementMatrix(m, n, this::genRandomZqElementMember));
	}

	/**
	 * Generate a {@link GroupMatrix} of {@link ZqElement} in this {@code group}. Populated with {@code element}
	 *
	 * @param m        the matrix' number of lines.
	 * @param n        the matrix' number of columns.
	 * @param element, value with which the matrix is initialised
	 * @return a m &times; n matrix of defined {@link ZqElement}.
	 */
	public GroupMatrix<ZqElement, ZqGroup> initializeMatrixWithElement(final int m, final int n, final ZqElement element) {
		return GroupMatrix.fromRows(generateElementMatrix(m, n, () -> element));
	}
}
