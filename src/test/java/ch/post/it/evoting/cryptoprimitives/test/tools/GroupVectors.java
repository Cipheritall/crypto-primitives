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

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import ch.post.it.evoting.cryptoprimitives.GroupMatrix;
import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.GroupVectorElement;
import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;
import ch.post.it.evoting.cryptoprimitives.math.MathematicalGroup;

public class GroupVectors {

	/**
	 * Return a new GroupVector copy with the element i replaced with the provided element.
	 *
	 * @param vector  the vector to copy
	 * @param i       the element to set
	 * @param element the value to set it to
	 * @param <E>     the type of elements in this vector
	 * @param <G>     the group of these elements
	 * @return a new GroupVector with the ith element replaced.
	 */
	public static <E extends GroupVectorElement<G> & Hashable, G extends MathematicalGroup<G>>
	GroupVector<E, G> with(GroupVector<E, G> vector, int i, E element) {
		List<E> modifiedElements = new ArrayList<>(vector);
		modifiedElements.set(i, element);
		return GroupVector.from(modifiedElements);
	}

	/**
	 * Returns a new Matrix with the element (i, j) replaced
	 *
	 * @param matrix  the matrix to copy and modify
	 * @param i       the row index of the value to modify
	 * @param j       the column index of the value to modify
	 * @param element the new value
	 * @param <E>     the matrix element type
	 * @param <G>     the matrix element mathematical group type
	 * @return a new matrix with all elements copied from the initial matrix except element (i,j) with the new value
	 */
	public static <E extends GroupVectorElement<G> & Hashable, G extends MathematicalGroup<G>>
	GroupMatrix<E, G> with(GroupMatrix<E, G> matrix, int i, int j, E element) {
		List<List<E>> modifiedElements = matrix.rowStream().map(ArrayList::new).collect(Collectors.toList());
		modifiedElements.get(i).set(j, element);
		return GroupMatrix.fromRows(modifiedElements);
	}
}
