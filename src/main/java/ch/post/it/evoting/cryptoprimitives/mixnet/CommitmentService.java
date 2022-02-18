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

import static ch.post.it.evoting.cryptoprimitives.math.GroupVector.toGroupVector;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Collections;
import java.util.stream.IntStream;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupMatrix;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

/**
 * <p>This class is thread safe.</p>
 */
@SuppressWarnings("java:S117")
public class CommitmentService {

	private CommitmentService() {
		// intentionally left blank
	}

	/**
	 * Computes a commitment to the given elements with the given random element and <code>CommitmentKey</code>.
	 *
	 * <p>The input arguments must comply with the following:
	 * 		<ul>
	 * 		 	<li>be non null</li>
	 * 		 	<li>all the elements to be committed to and the random element must belong to the same <code>ZqGroup</code></li>
	 * 		 	<li>the <code>GqGroup</code> of the commitment key must have the same order <i>q</i> as the <code>ZqGroup</code> of the other inputs</li>
	 * 		 	<li>the vector of elements to be committed to must be non empty</li>
	 * 		 	<li>the commitment key must have at least the same size as the vector of elements to be committed to</li>
	 * 		</ul>
	 * </p>
	 *
	 * @param elements      a, the {@link ZqElement}s to be committed (a<sub>0</sub>, ..., a<sub>l</sub>)
	 * @param randomElement r, the random {@link ZqElement}
	 * @param commitmentKey <b>ck</b>, a {@link CommitmentKey} (h, g<sub>1</sub>, ..., g<sub>ν</sub>)
	 * @return the commitment to the provided elements as a {@link GqElement}
	 */
	static GqElement getCommitment(final GroupVector<ZqElement, ZqGroup> elements, final ZqElement randomElement, final CommitmentKey commitmentKey) {
		// Null checks.
		checkNotNull(elements);
		checkNotNull(randomElement);
		checkNotNull(commitmentKey);

		final GroupVector<ZqElement, ZqGroup> a = elements;
		final ZqElement r = randomElement;
		final CommitmentKey ck = commitmentKey;
		final int l = a.size();
		final int nu = ck.size();

		// By construction, commitmentKey.size() > 1.
		checkArgument(a.isEmpty() || a.getGroup().equals(r.getGroup()),
				"The random value must belong to the same group as the values to be committed to");
		checkArgument(r.getGroup().hasSameOrderAs(ck.getGroup()),
				"The commitment key must have the same order (q) as the elements to be committed to and the random value");
		checkArgument(nu >= l, "The commitment key must be equal to or longer than the list of elements to commit to");

		final GqElement h = ck.getH();
		final GroupVector<GqElement, GqGroup> g = ck.getG();
		// Due to 0 indexing of the gs, the indexes used deviate from the spec
		return h.exponentiate(r).multiply(IntStream.range(0, l).mapToObj(i -> g.get(i).exponentiate(a.get(i)))
				.reduce(ck.getGroup().getIdentity(), GqElement::multiply));
	}

	/**
	 * Computes a commitment to the given matrix with the given random elements and {@link CommitmentKey}.
	 *
	 * <p>The input arguments must comply with the following:
	 * 		<ul>
	 * 		 	<li>be non null</li>
	 * 			<li>there must be as many random elements as columns in the matrix of elements to be committed</li>
	 * 			<li>the commitment key must have at least as many g elements as rows in the matrix of elements to be committed</li>
	 * 			<li>all inputs must have the same group order <i>q</i></li>
	 * 		</ul>
	 * </p>
	 *
	 * @param elements       A, the non empty matrix of {@link ZqElement}s to be committed of <i>n</i> rows and <i>m</i> columns.
	 * @param randomElements <b>r</b>, the non empty vector of <i>m</i> randomly chosen {@link ZqElement}s to be used for the commitment.
	 * @param commitmentKey  <b>ck</b>, the commitment key of the form (h, g<sub>1</sub>, ..., g<sub>ν</sub>), ν >= n.
	 * @return the commitments (c<sub>0</sub>, ..., c<sub>m-1</sub>)
	 */
	static GroupVector<GqElement, GqGroup> getCommitmentMatrix(final GroupMatrix<ZqElement, ZqGroup> elements,
			final GroupVector<ZqElement, ZqGroup> randomElements, final CommitmentKey commitmentKey) {

		checkNotNull(elements);
		checkNotNull(randomElements);
		checkNotNull(commitmentKey);

		final GroupMatrix<ZqElement, ZqGroup> A = elements;
		final GroupVector<ZqElement, ZqGroup> r = randomElements;
		final CommitmentKey ck = commitmentKey;
		final int n = A.numRows();
		final int m = A.numColumns();
		final int nu = ck.size();

		// Cross arguments dimension checking.
		checkArgument(r.size() == m, "There must be as many random elements as there are columns in the element matrix");
		checkArgument(nu >= n, "The commitment key must be longer than the number of rows of the elements matrix");

		// Cross arguments group checking.
		checkArgument(A.getGroup().equals(r.getGroup()),
				"The elements to be committed to and the random elements must be in the same group.");
		checkArgument(A.getGroup().hasSameOrderAs(ck.getGroup()),
				"The commitment key must have the same order (q) than the elements to be committed to and the random values");

		// Algorithm.
		return IntStream.range(0, m)
				.mapToObj(i -> {
					final GroupVector<ZqElement, ZqGroup> a_i = A.getColumn(i);
					final ZqElement r_i = r.get(i);
					return getCommitment(a_i, r_i, ck);
				})
				.collect(toGroupVector());
	}

	/**
	 * Computes a commitment to the given vector with the given random elements and {@link CommitmentKey}.
	 *
	 * <p>The input arguments must comply with the following:
	 * 		<ul>
	 * 			<li>be non null</li>
	 * 			<li>be non empty</li>
	 * 			<li>the vector of elements to be committed and the random elements vector must have the same size</li>
	 * 			<li>all inputs must have the same group order <i>q</i></li>
	 * 		</ul>
	 * </p>
	 *
	 * @param elements       <b>d</b>, the vector of <i>2m+1</i> {@link ZqElement}s to be committed to.
	 * @param randomElements <b>t</b>, the non empty vector of <i>2m+1</i> randomly chosen {@link ZqElement}s to be used for the commitment.
	 * @param commitmentKey  <b>ck</b>, the {@link CommitmentKey} of size ν &ge; 1.
	 * @return the commitment c = (c<sub>0</sub>, ..., c<sub>2m</sub>)
	 */
	static GroupVector<GqElement, GqGroup> getCommitmentVector(final GroupVector<ZqElement, ZqGroup> elements,
			final GroupVector<ZqElement, ZqGroup> randomElements, final CommitmentKey commitmentKey) {

		checkNotNull(elements);
		checkNotNull(randomElements);
		checkNotNull(commitmentKey);

		final GroupVector<ZqElement, ZqGroup> d = elements;
		final GroupVector<ZqElement, ZqGroup> t = randomElements;
		final CommitmentKey ck = commitmentKey;

		final GroupMatrix<ZqElement, ZqGroup> d_matrix = GroupMatrix.fromRows(Collections.singletonList(d));

		// Cross dimension checking.
		checkArgument(d_matrix.numColumns() == t.size(),
				"The elements vector and the random elements must be of equal length");

		// Cross group checking.
		checkArgument(d_matrix.getGroup().equals(t.getGroup()),
				"The elements to be committed to and the random elements must be in the same group.");
		checkArgument(d_matrix.getGroup().hasSameOrderAs(ck.getGroup()),
				"The commitment key must have the same order (q) than the elements to be committed to and the random values");

		return getCommitmentMatrix(d_matrix, t, ck);
	}
}
