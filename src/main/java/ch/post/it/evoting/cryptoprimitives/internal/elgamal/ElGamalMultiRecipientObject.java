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
package ch.post.it.evoting.cryptoprimitives.internal.elgamal;

import java.util.stream.Stream;

import ch.post.it.evoting.cryptoprimitives.internal.math.MathematicalGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupElement;
import ch.post.it.evoting.cryptoprimitives.math.GroupVectorElement;

/**
 * Defines a common API for El Gamal multi-recipient objects.
 */
public interface ElGamalMultiRecipientObject<E extends GroupElement<G>, G extends MathematicalGroup<G>> extends GroupVectorElement<G> {

	@Override
	G getGroup();

	/**
	 * @return the size of this actor.
	 */
	int size();

	/**
	 * @param i the index of the element to return
	 * @return the ith element of this actor.
	 */
	E get(final int i);

	/**
	 * @return an ordered stream of this object's elements.
	 */
	Stream<E> stream();
}
