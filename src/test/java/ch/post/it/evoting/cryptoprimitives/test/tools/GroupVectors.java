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

import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.GroupVectorElement;
import ch.post.it.evoting.cryptoprimitives.Hashable;
import ch.post.it.evoting.cryptoprimitives.math.MathematicalGroup;

public class GroupVectors {

	/**
	 * Return a new SameGroupVector copy with the element i replaced with the provided element.
	 * @param vector the vector to copy
	 * @param i the element to set
	 * @param element the value to set it to
	 * @param <E> the type of elements in this vector
	 * @param <G> the group of these elements
	 * @return a new SameGroupVector with the ith element replaced.
	 */
	public static <E extends GroupVectorElement<G> & Hashable, G extends MathematicalGroup<G>>
	SameGroupVector<E, G> set(SameGroupVector<E, G> vector, int i, E element) {
		List<E> modifiedElements = new ArrayList<>(vector);
		modifiedElements.set(i, element);
		return SameGroupVector.from(modifiedElements);
	}
}
