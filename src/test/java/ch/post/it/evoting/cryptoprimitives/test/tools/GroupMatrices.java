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
package ch.post.it.evoting.cryptoprimitives.test.tools;

import static java.util.stream.Collectors.toList;

import java.util.ArrayList;
import java.util.List;

import ch.post.it.evoting.cryptoprimitives.SameGroupMatrix;
import ch.post.it.evoting.cryptoprimitives.GroupVectorElement;
import ch.post.it.evoting.cryptoprimitives.Hashable;
import ch.post.it.evoting.cryptoprimitives.math.MathematicalGroup;

public class GroupMatrices {

	/**
	 * Return a new SameGroupMatrix copy with the element i replaced with the provided element.
	 * @param matrix the matrix to modify
	 * @param i the row of the element to set
	 * @param j the column of the element to set
	 * @param element the value to set it to
	 * @param <E> the type of elements in this vector
	 * @param <G> the group of these elements
	 * @return a new SameGroupMatrix with the (i, j) element replaced.
	 */
	public static <E extends GroupVectorElement<G> & Hashable, G extends MathematicalGroup<G>>
	SameGroupMatrix<E, G> set(SameGroupMatrix<E, G> matrix, int i, int j, E element) {
		List<List<E>> modifiedElements = matrix.rowStream().map(ArrayList::new).collect(toList());
		modifiedElements.get(i).set(j, element);
		return SameGroupMatrix.fromRows(modifiedElements);
	}
}
