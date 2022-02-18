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

import static com.google.common.base.Preconditions.checkNotNull;

import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ch.post.it.evoting.cryptoprimitives.math.GroupVectorElement;
import ch.post.it.evoting.cryptoprimitives.math.MathematicalGroup;

public class GroupVectorElementGenerator {

	/**
	 * Generate a list of {@link GroupVectorElement} elements.
	 *
	 * @param numElements the number of elements to generate
	 * @param s the supplier to create a single element
	 * @param <E> the element type
	 * @param <G> the element group
	 * @return a list of elements
	 */
	public static <E extends GroupVectorElement<G>, G extends MathematicalGroup<G>> List<E> generateElementList(final int numElements, Supplier<E> s) {
		return Stream.generate(s).limit(numElements).collect(Collectors.toList());
	}

	/**
	 * Generate a matrix of {@link GroupVectorElement} elements.
	 *
	 * @param numRows the number of rows to generate
	 * @param numColumns the number of columns to generate
	 * @param s the supplier of a single element
	 * @param <E> the element type
	 * @param <G> the element group type
	 * @return a matrix of elements, row by row.
	 */
	public static <E extends GroupVectorElement<G>, G extends MathematicalGroup<G>>
	List<List<E>> generateElementMatrix(final int numRows, final int numColumns, Supplier<E> s) {
		checkNotNull(s);
		return Stream.generate(() -> generateElementList(numColumns, s)).limit(numRows).collect(Collectors.toList());
	}
}
