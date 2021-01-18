/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.BigIntegerOperations;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

public class CommitmentService {

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
	 * @param elements 		a, the {@link ZqElement}s to be committed (a<sub>0</sub>, ..., a<sub>l</sub>)
	 * @param randomElement r, the random {@link ZqElement}
	 * @param commitmentKey	<b>ck</b>, a {@link CommitmentKey} (h, g<sub>1</sub>, ..., g<sub>k</sub>)
	 * @return	the commitment to the provided elements as a {@link GqElement}
	 */
	GqElement getCommitment(final List<ZqElement> values, final ZqElement randomElement, final CommitmentKey commitmentKey) {
		//Null checks
		checkNotNull(values);
		checkNotNull(randomElement);
		checkNotNull(commitmentKey);
		checkArgument(values.stream().allMatch(Objects::nonNull), "Values to be committed to cannot be null");

		//Immutable copy and values group check
		SameGroupVector<ZqElement, ZqGroup> valuesVector = new SameGroupVector<>(values);

		// by construction, commitmentKey.size() > 1
		checkArgument(valuesVector.isEmpty() || valuesVector.getGroup().equals(randomElement.getGroup()),
				"The random value must belong to the same group as the values to be committed to");
		checkArgument(randomElement.getGroup().getQ().equals(commitmentKey.getGroup().getQ()),
				"The commitment key must have the same order (q) as the elements to be committed to and the random value");
		int l = valuesVector.size();
		int k = commitmentKey.size();
		checkArgument(k >= l, "The commitment key must be equal to or longer than the list of elements to commit to");

		List<BigInteger> commitmentKeyValues =
				Stream.concat(Stream.of(commitmentKey.getH()), commitmentKey.stream())
						.map(GroupElement::getValue)
						.collect(Collectors.toList());
		GqGroup group = commitmentKey.getGroup();
		BigInteger p = group.getP();

		List<BigInteger> commitmentValues =
				Stream.concat(Stream.of(randomElement), valuesVector.stream())
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
	 * 			<li>be non null</li>
	 * 			<li>be non empty</li>
	 * 			<li>all rows of the element matrix must have the same length</li>
	 * 			<li>there must be as many random elements as rows in the matrix of elements to be committed</li>
	 * 			<li>the commitment key must have at least as many g elements as columns in the matrix of elements to be committed</li>
	 * 			<li>all inputs must have the same group order <i>q</i></li>
	 * 		</ul>
	 * </p>
	 *
	 * @param elementsMatrix	A, the non empty matrix of {@link ZqElement}s to be committed of <i>m</i> rows and <i>n</i> columns.
	 * @param randomElements	<b>r</b>, the non empty vector of <i>m</i> randomly chosen {@link ZqElement}s to be used for the commitment.
	 * @param commitmentKey		<b>ck</b>, the commitment key of the form (h, g<sub>1</sub>, ..., g<sub>k</sub>), k >= n.
	 * @return	the commitments (c<sub>0</sub>, ..., c<sub>m-1</sub>)
	 */
	List<GqElement> getCommitmentMatrix(final List<List<ZqElement>> elementsMatrix, final List<ZqElement> randomElements, final CommitmentKey commitmentKey) {
		checkNotNull(elementsMatrix);
		checkNotNull(randomElements);
		checkNotNull(commitmentKey);

		checkArgument(elementsMatrix.stream().allMatch(Objects::nonNull), "Rows must not be null");
		checkArgument(elementsMatrix.stream().flatMap(Collection::stream).allMatch(Objects::nonNull), "Elements must not be null");

		final ImmutableList<ImmutableList<ZqElement>> elementsMatrixCopy = elementsMatrix.stream()
				.map(ImmutableList::copyOf)
				.collect(ImmutableList.toImmutableList());
		checkArgument(!elementsMatrixCopy.isEmpty(), "The elements matrix must have at least one row");
		checkArgument(elementsMatrixCopy.stream().noneMatch(List::isEmpty), "The elements matrix must not have any empty rows");

		checkArgument(randomElements.stream().allMatch(Objects::nonNull), "Random elements must not be null");
		final ImmutableList<ZqElement> randomElementsCopy = ImmutableList.copyOf(randomElements);

		int n = elementsMatrixCopy.get(0).size();
		int m = elementsMatrixCopy.size();
		int k = commitmentKey.size();

		// Dimension checking
		checkArgument(elementsMatrixCopy.stream().allMatch(row -> row.size() == n),
				"All rows of the elements matrix must have the same size.");
		checkArgument(randomElementsCopy.size() == m,
				"There must be as many random elements as there are rows in the element matrix");
		checkArgument(k >= n, "The commitment key must be longer than the number of columns of the elements matrix");

		// Group checking.
		final ZqGroup elementsZqGroup = elementsMatrixCopy.get(0).get(0).getGroup();
		final ZqGroup randomZqGroup = randomElementsCopy.get(0).getGroup();
		checkArgument(elementsMatrixCopy.stream().flatMap(Collection::stream).map(ZqElement::getGroup).allMatch(elementsZqGroup::equals),
				"All elements to be committed must be in the same group.");
		checkArgument(randomElementsCopy.stream().map(ZqElement::getGroup).allMatch(randomZqGroup::equals),
				"All random elements must be in the same group.");
		checkArgument(elementsZqGroup.equals(randomZqGroup), "The elements to be committed to and the random elements must be in the same group.");
		checkArgument(elementsZqGroup.getQ().equals(commitmentKey.getGroup().getQ()),
				"The commitment key must have the same order (q) than the elements to be committed to and the random values");

		return IntStream.range(0, m)
				.mapToObj(i -> getCommitment(elementsMatrixCopy.get(i), randomElementsCopy.get(i), commitmentKey))
				.collect(Collectors.toList());
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
	 * @param elementsVector	<b>d</b>, the vector of <i>2m+1</i> {@link ZqElement}s to be committed to.
	 * @param randomElements	<b>t</b>, the non empty vector of <i>2m+1</i> randomly chosen {@link ZqElement}s to be used for the commitment.
	 * @param commitmentKey		<b>ck</b>, the {@link CommitmentKey} of size k &ge; 1.
	 * @return	the commitment c = (c<sub>0</sub>, ..., c<sub>2m</sub>)
	 */
	List<GqElement> getCommitmentVector(final List<ZqElement> elementsVector, final List<ZqElement> randomElements, final CommitmentKey commitmentKey) {
		checkNotNull(elementsVector);
		checkNotNull(randomElements);
		checkNotNull(commitmentKey);
		// The size and the group of the commitment key are checked upon its construction
		checkArgument(elementsVector.stream().allMatch(Objects::nonNull));

		ImmutableList<List<ZqElement>> vector = elementsVector.stream()
				.map(ImmutableList::of)
				.collect(ImmutableList.toImmutableList());
		checkArgument(!vector.isEmpty());
		checkArgument(vector.stream().noneMatch(List::isEmpty));

		ImmutableList<ZqElement> randomElementsCopy = ImmutableList.copyOf(randomElements);

		// Dimension checking
		checkArgument(vector.stream().allMatch(row -> row.size() == 1),
				"All rows of the elements matrix must have the same size.");
		checkArgument(vector.size() == randomElementsCopy.size(), "The elements vector and the random elements must be of equal length");


		// Group checking.
		final ZqGroup vectorZqGroup = vector.get(0).get(0).getGroup();
		final ZqGroup randomZqGroup = randomElementsCopy.get(0).getGroup();
		checkArgument(vector.stream().flatMap(Collection::stream).map(ZqElement::getGroup).allMatch(vectorZqGroup::equals),
				"All elements to be committed must be in the same group.");
		checkArgument(randomElementsCopy.stream().map(ZqElement::getGroup).allMatch(randomZqGroup::equals),
				"All random elements must be in the same group.");
		checkArgument(vectorZqGroup.equals(randomZqGroup), "The elements to be committed to and the random elements must be in the same group.");
		checkArgument(vectorZqGroup.getQ().equals(commitmentKey.getGroup().getQ()),
				"The commitment key must have the same order (q) than the elements to be committed to and the random values");


		return getCommitmentMatrix(vector, randomElements, commitmentKey);
	}
}
