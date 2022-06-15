/*
 * Copyright 2022 Post CH Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import ch.post.it.evoting.cryptoprimitives.math.GroupMatrix;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

/**
 * <p>Instances of this class are immutable. </p>
 */
@SuppressWarnings({"java:S100", "java:S116"})
public
class HadamardWitness {

	private final GroupMatrix<ZqElement, ZqGroup> A;
	private final GroupVector<ZqElement, ZqGroup> b;
	private final GroupVector<ZqElement, ZqGroup> r;
	private final ZqElement s;

	/**
	 * Constructs a {@code HadamardWitness} object.
	 * <p>
	 * The inputs must comply with the following:
	 * <ul>
	 *     <li>be non null</li>
	 *     <li>belong to the same {@link ZqGroup}</li>
	 *     <li>the number of rows of the matrix and the vector size must be equal</li>
	 *     <li>the number of columns of the matrix and the size of the exponents vector must be equal</li>
	 * </ul>
	 *
	 * @param matrix     A, a matrix of {@code ZqElements} of size <i>n</i> &times; <i>m</i>
	 * @param vector     b, a vector of {@code ZqElements} of size <i>n</i>
	 * @param exponents  r, a vector of {@code ZqElements} of size <i>m</i>
	 * @param randomness s, a {@code ZqElement}
	 */
	public HadamardWitness(final GroupMatrix<ZqElement, ZqGroup> matrix, final GroupVector<ZqElement, ZqGroup> vector,
			final GroupVector<ZqElement, ZqGroup> exponents, final ZqElement randomness) {
		checkNotNull(matrix);
		checkNotNull(vector);
		checkNotNull(exponents);
		checkNotNull(randomness);

		this.A = matrix;
		this.b = vector;
		this.r = exponents;
		this.s = randomness;

		// Dimension checks
		checkArgument(A.numRows() == b.size(),
				"The matrix A must have the same number of rows as the vector b has elements.");
		checkArgument(A.numColumns() == r.size(),
				"The matrix A must have the same number of columns as the exponents r have elements.");

		// Group checks
		checkArgument(A.getGroup().equals(b.getGroup()),
				"The matrix A and the vector b must have the same group.");
		checkArgument(A.getGroup().equals(r.getGroup()),
				"The matrix A and the exponents r must have the same group.");
		checkArgument(r.getGroup().equals(s.getGroup()),
				"The exponents r and the exponent s must have the same group.");
	}

	public GroupMatrix<ZqElement, ZqGroup> get_A() {
		return A;
	}

	public GroupVector<ZqElement, ZqGroup> get_b() {
		return b;
	}

	public GroupVector<ZqElement, ZqGroup> get_r() {
		return r;
	}

	public ZqElement get_s() {
		return s;
	}
}
