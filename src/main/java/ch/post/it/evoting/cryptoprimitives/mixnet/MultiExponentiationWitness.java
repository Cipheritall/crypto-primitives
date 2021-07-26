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
 * Value class representing a witness for the multi exponentiation argument.
 * <p>
 * Instances of this class are immutable.
 */
@SuppressWarnings({"java:S100", "java:S116", "java:S117"})
final class MultiExponentiationWitness {

	private final GroupMatrix<ZqElement, ZqGroup> A;
	private final GroupVector<ZqElement, ZqGroup> r;
	private final ZqElement rho;

	private final ZqGroup group;
	private final int m;
	private final int n;

	/**
	 * <p>Creates a multi-exponentiation witness.</p>
	 * <p>
	 * Parameters must abide by the following conditions:
	 * <ul>
	 *     <li>must be non null</li>
	 *     <li>must belong to the same ZqGroup</li>
	 * </ul>
	 *
	 * @param A     A, the exponents matrix, of size n x m
	 * @param r  r, a vector of exponents of size m
	 * @param rho ρ, the re-encrypting exponent
	 */
	MultiExponentiationWitness(final GroupMatrix<ZqElement, ZqGroup> A, final GroupVector<ZqElement, ZqGroup> r, final ZqElement rho) {

		//Null checking
		checkNotNull(A);
		checkNotNull(r);
		checkNotNull(rho);

		//Dimension checking
		checkArgument(A.numColumns() == r.size(), "The matrix A number of columns must equals the number of exponents.");

		//Group checking
		checkArgument(A.getGroup().equals(r.getGroup()), "The matrix A and the exponents r must belong to the same group.");
		checkArgument(A.getGroup().equals(rho.getGroup()), "The matrix A and the exponent ρ must belong to the same group");

		this.A = A;
		this.r = r;
		this.rho = rho;

		this.group = A.getGroup();
		this.m = A.numColumns();
		this.n = A.numRows();
	}

	GroupMatrix<ZqElement, ZqGroup> get_A() {
		return A;
	}

	GroupVector<ZqElement, ZqGroup> get_r() {
		return r;
	}

	ZqElement get_rho() {
		return rho;
	}

	ZqGroup getGroup() {
		return group;
	}

	int get_m() {
		return m;
	}

	int get_n() {
		return n;
	}

	@Override
	public boolean equals(final Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		final MultiExponentiationWitness that = (MultiExponentiationWitness) o;
		return A.equals(that.A) && r.equals(that.r) && rho.equals(that.rho);
	}

	@Override
	public int hashCode() {
		return Objects.hash(A, r, rho);
	}
}
