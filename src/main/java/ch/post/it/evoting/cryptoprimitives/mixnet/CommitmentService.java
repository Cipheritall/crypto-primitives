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

import ch.post.it.evoting.cryptoprimitives.math.BigIntegerOperations;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

public class CommitmentService {

	/**
	 * <p>Computes a commitment to the given elements with the given commitment key.
	 * The commitment key must be at least as long as the number of elements to be committed.</p>
	 *
	 * @param elements 		a, the elements to be committed (a<sub>0</sub>, ..., a<sub>l</sub>)
	 * @param randomElement r, the random value
	 * @param commitmentKey	<b>ck</b>, a commitment key (h, g<sub>1</sub>, ..., g<sub>k</sub>)
	 * @return	the commitment to the provided elements as a {@link GqElement}
	 */
	GqElement getCommitment(final List<ZqElement> elements, final ZqElement randomElement, final CommitmentKey commitmentKey) {
		checkNotNull(elements);
		checkNotNull(randomElement);
		checkNotNull(commitmentKey);

		checkArgument(elements.stream().allMatch(Objects::nonNull), "Elements to be committed to cannot be null");
		ImmutableList<ZqElement> elementsCopy = ImmutableList.copyOf(elements);
		checkArgument(!elementsCopy.isEmpty(), "There must be at least one element to commit to");
		checkArgument(elementsCopy.stream().map(ZqElement::getGroup).allMatch(elementsCopy.get(0).getGroup()::equals),
				"All elements must belong to the same group");

		// by construction, commitmentKey.size() > 1
		checkArgument(elementsCopy.get(0).getGroup().equals(randomElement.getGroup()),
				"The random value must belong to the same group as the commitment elements");
		checkArgument(randomElement.getGroup().getQ().equals(commitmentKey.getGroup().getQ()),
				"The commitment key must have the same order (q) as the elements to be committed to and the random value");
		int l = elementsCopy.size();
		int k = commitmentKey.size();
		checkArgument(k >= l, "The commitment key must be equal to or longer than the list of elements to commit to");

		List<BigInteger> commitmentKeyValues =
				Stream.concat(Stream.of(commitmentKey.getH()), commitmentKey.getGElements().stream())
						.map(GroupElement::getValue)
						.collect(Collectors.toList());
		GqGroup group = commitmentKey.getGroup();
		BigInteger p = group.getP();

		List<BigInteger> commitmentValues =
				Stream.concat(Stream.of(randomElement), elementsCopy.stream())
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
	 * <p>Computes a commitment to the given matrix with the given commitment key.
	 * The commitment key must be at least as long as the number of columns in the matrix to be committed.</p>
	 *
	 * @param elementsMatrix	A, the matrix of {@link ZqElement}s to be committed of <i>m</i> rows and <i>n</i> columns
	 * @param randomElements	<b>r</b>, the vector of <i>m</i> randomly chosen {@link ZqElement}s to be used for the commitment
	 * @param commitmentKey		<b>ck</b>, the commitment key of the form (h, g<sub>1</sub>, ..., g<sub>k</sub>), k >= n
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
}
