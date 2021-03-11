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
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Objects;

import ch.post.it.evoting.cryptoprimitives.GroupMatrix;
import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

/**
 * Represents a witness for a product argument.
 */
class ProductWitness {

	private final GroupMatrix<ZqElement, ZqGroup> matrix;
	private final GroupVector<ZqElement, ZqGroup> exponents;

	/**
	 * Instantiates a {@link ProductWitness} with the given matrix and exponents.
	 *
	 * <p>The matrix and the exponents must comply with the following:
	 * <ul>
	 *     <li>be non null</li>
	 *     <li>belong to the same {@link ZqGroup}</li>
	 *     <li>the number of columns in the matrix must be equal to the number of exponents</li>
	 * </ul>
	 *
	 * @param matrix    A, a {@link GroupMatrix} of {@code ZqElements}
	 * @param exponents <b><i>r</i></b>, a {@link GroupVector} of {@code ZqElements}
	 */
	ProductWitness(final GroupMatrix<ZqElement, ZqGroup> matrix, final GroupVector<ZqElement, ZqGroup> exponents) {
		checkNotNull(matrix);
		checkNotNull(exponents);
		checkArgument(matrix.numColumns() == exponents.size(),
				"The number of columns in the matrix must be equal to the number of exponents.");
		checkArgument(matrix.getGroup().equals(exponents.getGroup()),
				"The matrix and the exponents must belong to the same group.");

		this.matrix = matrix;
		this.exponents = exponents;
	}

	GroupMatrix<ZqElement, ZqGroup> getMatrix() {
		return matrix;
	}

	GroupVector<ZqElement, ZqGroup> getExponents() {
		return exponents;
	}

	@Override
	public boolean equals(final Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		final ProductWitness that = (ProductWitness) o;
		return matrix.equals(that.matrix) && exponents.equals(that.exponents);
	}

	@Override
	public int hashCode() {
		return Objects.hash(matrix, exponents);
	}
}
