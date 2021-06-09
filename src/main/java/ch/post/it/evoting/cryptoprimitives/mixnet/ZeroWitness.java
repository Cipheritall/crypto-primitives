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
 * Represents the witness for a zero argument, consisting of two matrices and two vectors of exponents.
 */
@SuppressWarnings({"java:S100", "java:S116", "java:S117"})
class ZeroWitness {

	private final GroupMatrix<ZqElement, ZqGroup> A;
	private final GroupMatrix<ZqElement, ZqGroup> B;
	private final GroupVector<ZqElement, ZqGroup> r;
	private final GroupVector<ZqElement, ZqGroup> s;

	/**
	 * Instantiates a zero witness. The matrices and exponents must comply with the following:
	 *
	 * <ul>
	 *     <li>be non null</li>
	 *     <li>the matrices must have the same number of rows and columns</li>
	 *     <li>the exponents vector must have the same size</li>
	 *     <li>the size of exponents vector must be the number of columns of the matrices</li>
	 * </ul>
	 *
	 * @param A    a matrix of {@link ZqElement}s.
	 * @param B    a matrix of {@link ZqElement}s.
	 * @param r    a vector of {@link ZqElement}s.
	 * @param s    a vector of {@link ZqElement}s.
	 */
	ZeroWitness(final GroupMatrix<ZqElement, ZqGroup> A, final GroupMatrix<ZqElement, ZqGroup> B,
			final GroupVector<ZqElement, ZqGroup> r, final GroupVector<ZqElement, ZqGroup> s) {

		// Null checking.
		this.A = checkNotNull(A);
		this.B = checkNotNull(B);
		this.r = checkNotNull(r);
		this.s = checkNotNull(s);

		// Cross dimensions checking.
		checkArgument(this.A.numRows() == this.B.numRows(), "The two matrices must have the same number of rows.");
		checkArgument(this.A.numColumns() == this.B.numColumns(), "The two matrices must have the same number of columns.");
		checkArgument(this.r.size() == this.s.size(), "The exponents vector must have the same size.");
		checkArgument(this.r.size() == this.A.numColumns(),
				"The exponents vectors size must be the number of columns of the matrices.");

		// Cross group checking.
		if (!this.A.isEmpty()) {
			final ZqGroup group = this.A.getGroup();
			checkArgument(this.B.getGroup().equals(group), "The matrices are not from the same group.");
			checkArgument(this.r.getGroup().equals(this.s.getGroup()), "The exponents are not from the same group.");
			checkArgument(this.r.getGroup().equals(group), "The matrices and exponents are not from the same group.");
		}
	}

	GroupMatrix<ZqElement, ZqGroup> get_A() {
		return A;
	}

	GroupMatrix<ZqElement, ZqGroup> get_B() {
		return B;
	}

	GroupVector<ZqElement, ZqGroup> get_r() {
		return r;
	}

	GroupVector<ZqElement, ZqGroup> get_s() {
		return s;
	}

	@Override
	public boolean equals(final Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		final ZeroWitness that = (ZeroWitness) o;
		return A.equals(that.A) && B.equals(that.B) && r.equals(that.r) && s
				.equals(that.s);
	}

	@Override
	public int hashCode() {
		return Objects.hash(A, B, r, s);
	}
}
