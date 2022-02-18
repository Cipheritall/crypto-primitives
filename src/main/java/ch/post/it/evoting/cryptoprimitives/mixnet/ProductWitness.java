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
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Objects;

import ch.post.it.evoting.cryptoprimitives.math.GroupMatrix;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

/**
 * Represents a witness for a product argument.
 *
 * <p>Instances of this class are immutable.</p>
 */
@SuppressWarnings({ "java:S100", "java:S116", "java:S117" })
class ProductWitness {

	private final GroupMatrix<ZqElement, ZqGroup> A;
	private final GroupVector<ZqElement, ZqGroup> r;

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
	 * @param A A, a {@link GroupMatrix} of {@code ZqElements}
	 * @param r <b><i>r</i></b>, a {@link GroupVector} of {@code ZqElements}
	 */
	ProductWitness(final GroupMatrix<ZqElement, ZqGroup> A, final GroupVector<ZqElement, ZqGroup> r) {
		checkNotNull(A);
		checkNotNull(r);
		checkArgument(A.numColumns() == r.size(),
				"The number of columns in the matrix must be equal to the number of exponents.");
		checkArgument(A.getGroup().equals(r.getGroup()),
				"The matrix and the exponents must belong to the same group.");

		this.A = A;
		this.r = r;
	}

	GroupMatrix<ZqElement, ZqGroup> get_A() {
		return A;
	}

	GroupVector<ZqElement, ZqGroup> get_r() {
		return r;
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
		return A.equals(that.A) && r.equals(that.r);
	}

	@Override
	public int hashCode() {
		return Objects.hash(A, r);
	}
}
