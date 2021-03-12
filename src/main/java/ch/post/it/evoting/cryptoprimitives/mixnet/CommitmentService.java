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

import static ch.post.it.evoting.cryptoprimitives.GroupVector.toSameGroupVector;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import ch.post.it.evoting.cryptoprimitives.GroupMatrix;
import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.BigIntegerOperations;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

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
	 * @param values        a, the {@link ZqElement}s to be committed (a<sub>0</sub>, ..., a<sub>l</sub>)
	 * @param randomElement r, the random {@link ZqElement}
	 * @param commitmentKey <b>ck</b>, a {@link CommitmentKey} (h, g<sub>1</sub>, ..., g<sub>k</sub>)
	 * @return the commitment to the provided elements as a {@link GqElement}
	 */
	static GqElement getCommitment(final GroupVector<ZqElement, ZqGroup> values, final ZqElement randomElement,
			final CommitmentKey commitmentKey) {
		// Null checks.
		checkNotNull(values);
		checkNotNull(randomElement);
		checkNotNull(commitmentKey);

		// By construction, commitmentKey.size() > 1.
		checkArgument(values.isEmpty() || values.getGroup().equals(randomElement.getGroup()),
				"The random value must belong to the same group as the values to be committed to");
		checkArgument(randomElement.getGroup().getQ().equals(commitmentKey.getGroup().getQ()),
				"The commitment key must have the same order (q) as the elements to be committed to and the random value");
		int l = values.size();
		int k = commitmentKey.size();
		checkArgument(k >= l, "The commitment key must be equal to or longer than the list of elements to commit to");

		List<BigInteger> commitmentKeyValues =
				commitmentKey.stream()
						.map(GroupElement::getValue)
						.collect(Collectors.toList());
		GqGroup group = commitmentKey.getGroup();
		BigInteger p = group.getP();

		List<BigInteger> commitmentValues =
				Stream.concat(Stream.of(randomElement), values.stream())
						.map(GroupElement::getValue)
						.collect(Collectors.toList());

		BigInteger c;
		if (l == k) {
			c = BigIntegerOperations.multiModExp(commitmentKeyValues, commitmentValues, p);
		} else {
			commitmentValues.addAll(Collections.nCopies(k - l, BigInteger.ZERO));
			c = BigIntegerOperations.multiModExp(commitmentKeyValues, commitmentValues, p);
		}
		return GqElement.create(c, group);
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
	 * @param elementsMatrix A, the non empty matrix of {@link ZqElement}s to be committed of <i>n</i> rows and <i>m</i> columns.
	 * @param randomElements <b>r</b>, the non empty vector of <i>m</i> randomly chosen {@link ZqElement}s to be used for the commitment.
	 * @param commitmentKey  <b>ck</b>, the commitment key of the form (h, g<sub>1</sub>, ..., g<sub>k</sub>), k >= n.
	 * @return the commitments (c<sub>0</sub>, ..., c<sub>m-1</sub>)
	 */
	static GroupVector<GqElement, GqGroup> getCommitmentMatrix(final GroupMatrix<ZqElement, ZqGroup> elementsMatrix,
			final GroupVector<ZqElement, ZqGroup> randomElements, final CommitmentKey commitmentKey) {

		// Check nullity.
		checkNotNull(elementsMatrix);
		checkNotNull(randomElements);
		checkNotNull(commitmentKey);

		// Handle empty matrix.
		if (elementsMatrix.isEmpty()) {
			return GroupVector.of();
		}

		// Cross arguments dimension checking.
		int n = elementsMatrix.numRows();
		int m = elementsMatrix.numColumns();
		int k = commitmentKey.size();

		checkArgument(randomElements.size() == m, "There must be as many random elements as there are columns in the element matrix");
		checkArgument(k >= n, "The commitment key must be longer than the number of rows of the elements matrix");

		// Cross arguments group checking.
		checkArgument(elementsMatrix.getGroup().equals(randomElements.getGroup()),
				"The elements to be committed to and the random elements must be in the same group.");
		checkArgument(elementsMatrix.getGroup().getQ().equals(commitmentKey.getGroup().getQ()),
				"The commitment key must have the same order (q) than the elements to be committed to and the random values");

		// Algorithm.
		return IntStream.range(0, m)
				.mapToObj(i -> getCommitment(elementsMatrix.getColumn(i), randomElements.get(i), commitmentKey))
				.collect(toSameGroupVector());
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
	 * @param elementsVector <b>d</b>, the vector of <i>2m+1</i> {@link ZqElement}s to be committed to.
	 * @param randomElements <b>t</b>, the non empty vector of <i>2m+1</i> randomly chosen {@link ZqElement}s to be used for the commitment.
	 * @param commitmentKey  <b>ck</b>, the {@link CommitmentKey} of size k &ge; 1.
	 * @return the commitment c = (c<sub>0</sub>, ..., c<sub>2m</sub>)
	 */
	static GroupVector<GqElement, GqGroup> getCommitmentVector(final GroupVector<ZqElement, ZqGroup> elementsVector,
			final GroupVector<ZqElement, ZqGroup> randomElements, final CommitmentKey commitmentKey) {

		checkNotNull(elementsVector);
		checkNotNull(randomElements);
		checkNotNull(commitmentKey);

		final List<List<ZqElement>> rows = Collections.singletonList(elementsVector.stream().collect(Collectors.toList()));
		GroupMatrix<ZqElement, ZqGroup> elementsMatrix = GroupMatrix.fromRows(rows);

		// Cross dimension checking.
		checkArgument(elementsMatrix.numColumns() == randomElements.size(),
				"The elements vector and the random elements must be of equal length");

		checkArgument(!elementsMatrix.isEmpty(), "getCommitmentVector is not defined on an empty matrix.");

		// Cross group checking.
		checkArgument(elementsMatrix.getGroup().equals(randomElements.getGroup()),
				"The elements to be committed to and the random elements must be in the same group.");
		checkArgument(elementsMatrix.getGroup().getQ().equals(commitmentKey.getGroup().getQ()),
				"The commitment key must have the same order (q) than the elements to be committed to and the random values");

		return getCommitmentMatrix(elementsMatrix, randomElements, commitmentKey);
	}
}
