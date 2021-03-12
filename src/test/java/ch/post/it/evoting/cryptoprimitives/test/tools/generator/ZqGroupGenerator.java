/*
 * Copyright 2021 Post CH Ltd
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

	public ZqElement otherElement(ZqElement element) {
		return Generators.genWhile(this::genRandomZqElementMember, element::equals);
	}

	/**
	 * Generate a random {@link SameGroupVector} of {@link ZqElement} in this {@code group}.
	 *
	 * @param numElements the number of elements to generate.
	 * @return a vector of {@code numElements} random {@link ZqElement}.
	 */
	public SameGroupVector<ZqElement, ZqGroup> genRandomZqElementVector(final int numElements) {
		return SameGroupVector.from(generateElementList(numElements, this::genRandomZqElementMember));
	}

	/**
	 * Generate a  {@link SameGroupVector} of {@link ZqElement} in this {@code group}. Populated with {@code element}
	 *
	 * @param numElements the number of elements to generate.
	 * @param element,    value with which the matrix is initialised
	 * @return a vector of {@code numElements} defined {@link ZqElement}.
	 */
	public SameGroupVector<ZqElement, ZqGroup> initializeElementVectorWithElement(final int numElements, ZqElement element) {
		return SameGroupVector.from(generateElementList(numElements, () -> element));
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
