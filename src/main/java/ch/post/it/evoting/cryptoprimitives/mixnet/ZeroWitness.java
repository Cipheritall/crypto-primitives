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

import ch.post.it.evoting.cryptoprimitives.SameGroupMatrix;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

/**
 * Represents the witness for a zero argument, consisting of two matrices and two vectors of exponents.
 */
class ZeroWitness {

	private final SameGroupMatrix<ZqElement, ZqGroup> matrixA;
	private final SameGroupMatrix<ZqElement, ZqGroup> matrixB;
	private final SameGroupVector<ZqElement, ZqGroup> exponentsR;
	private final SameGroupVector<ZqElement, ZqGroup> exponentsS;

	/**
	 * Instantiate a zero witness. The matrices and exponents must comply with the following:
	 *
	 * <ul>
	 *     <li>be non null</li>
	 *     <li>the matrices must have the same number of rows and columns</li>
	 *     <li>the exponents vector must have the same size</li>
	 *     <li>the size of exponents vector must be the number of columns of the matrices</li>
	 * </ul>
	 *
	 * @param matrixA    A, a matrix of {@link ZqElement}s.
	 * @param matrixB    B, a matrix of {@link ZqElement}s.
	 * @param exponentsR r, a vector of {@link ZqElement}s.
	 * @param exponentsS s, a vector of {@link ZqElement}s.
	 */
	ZeroWitness(final SameGroupMatrix<ZqElement, ZqGroup> matrixA, final SameGroupMatrix<ZqElement, ZqGroup> matrixB,
			final SameGroupVector<ZqElement, ZqGroup> exponentsR, SameGroupVector<ZqElement, ZqGroup> exponentsS) {

		// Null checking.
		this.matrixA = checkNotNull(matrixA);
		this.matrixB = checkNotNull(matrixB);
		this.exponentsR = checkNotNull(exponentsR);
		this.exponentsS = checkNotNull(exponentsS);

		// Cross dimensions checking.
		checkArgument(this.matrixA.numRows() == this.matrixB.numRows(), "The two matrices must have the same number of rows.");
		checkArgument(this.matrixA.numColumns() == this.matrixB.numColumns(), "The two matrices must have the same number of columns.");
		checkArgument(this.exponentsR.size() == this.exponentsS.size(), "The exponents vector must have the same size.");
		checkArgument(this.exponentsR.size() == this.matrixA.numColumns(),
				"The exponents vectors size must be the number of columns of the matrices.");

		// Cross group checking.
		if (!this.matrixA.isEmpty()) {
			final ZqGroup group = this.matrixA.getGroup();
			checkArgument(this.matrixB.getGroup().equals(group), "The matrices are not from the same group.");
			checkArgument(this.exponentsR.getGroup().equals(this.exponentsS.getGroup()), "The exponents are not from the same group.");
			checkArgument(this.exponentsR.getGroup().equals(group), "The matrices and exponents are not from the same group.");
		}
	}

	SameGroupMatrix<ZqElement, ZqGroup> getMatrixA() {
		return matrixA;
	}

	SameGroupMatrix<ZqElement, ZqGroup> getMatrixB() {
		return matrixB;
	}

	SameGroupVector<ZqElement, ZqGroup> getExponentsR() {
		return exponentsR;
	}

	SameGroupVector<ZqElement, ZqGroup> getExponentsS() {
		return exponentsS;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		ZeroWitness that = (ZeroWitness) o;
		return matrixA.equals(that.matrixA) && matrixB.equals(that.matrixB) && exponentsR.equals(that.exponentsR) && exponentsS
				.equals(that.exponentsS);
	}

	@Override
	public int hashCode() {
		return Objects.hash(matrixA, matrixB, exponentsR, exponentsS);
	}
}
