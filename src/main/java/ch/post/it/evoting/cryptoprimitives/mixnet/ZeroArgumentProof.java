/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.stream.IntStream;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

/**
 * Class in charge of providing a Zero Argument used in the Zero Argument proof.
 */
final class ZeroArgumentProof {

	private final ZqElement y;

	/**
	 * Construct a ZeroArgumentProof with a value {@code y} used by the starMap algorithm.
	 *
	 * @param y the value characterizing the bilinear mapping.
	 */
	ZeroArgumentProof(final ZqElement y) {
		checkNotNull(y);

		this.y = y;
	}

	/**
	 * Compute the vector <b>d</b> for the GetZeroArgument algorithm. The input matrices must comply to the following:
	 * <ul>
	 *     <li>be non null</li>
	 *     <li>each matrix row must have the same number of columns</li>
	 *     <li>both matrices must have the same number of lines and columns</li>
	 *     <li>all matrix elements must be part of the same group as the value y</li>
	 * </ul>
	 *
	 * @param firstMatrix  A, the first matrix.
	 * @param secondMatrix B, the second matrix.
	 * @return the computed <b>d</b> vector.
	 */
	List<ZqElement> computeDVector(final List<List<ZqElement>> firstMatrix, final List<List<ZqElement>> secondMatrix) {
		// Null checking and copies.
		checkNotNull(firstMatrix);
		checkNotNull(secondMatrix);
		checkArgument(firstMatrix.stream().allMatch(Objects::nonNull), "First matrix rows must not be null.");
		checkArgument(secondMatrix.stream().allMatch(Objects::nonNull), "Second matrix rows must not be null.");
		checkArgument(firstMatrix.stream().flatMap(Collection::stream).allMatch(Objects::nonNull), "First matrix elements must be not be null.");
		checkArgument(secondMatrix.stream().flatMap(Collection::stream).allMatch(Objects::nonNull), "Second matrix elements must be not be null.");
		final ImmutableList<ImmutableList<ZqElement>> firstMatrixCopy = firstMatrix.stream()
				.map(ImmutableList::copyOf)
				.collect(ImmutableList.toImmutableList());
		final ImmutableList<ImmutableList<ZqElement>> secondMatrixCopy = secondMatrix.stream()
				.map(ImmutableList::copyOf)
				.collect(ImmutableList.toImmutableList());

		// Dimensions checking.
		checkArgument(firstMatrixCopy.size() == secondMatrixCopy.size(), "The two matrices must have the same number of rows.");

		if (firstMatrixCopy.isEmpty()) {
			return Collections.emptyList();
		}

		checkArgument(firstMatrixCopy.stream().allMatch(row -> row.size() == firstMatrixCopy.get(0).size()),
				"All rows of the first matrix must have the same number of columns.");
		checkArgument(secondMatrixCopy.stream().allMatch(row -> row.size() == secondMatrixCopy.get(0).size()),
				"All rows of the second matrix must have the same number of columns.");
		checkArgument(firstMatrixCopy.get(0).size() == secondMatrixCopy.get(0).size(), "The two matrices must have the same number of columns.");

		if (firstMatrixCopy.get(0).isEmpty()) {
			return Collections.emptyList();
		}

		// Group checking.
		final ZqGroup firstZqGroup = firstMatrixCopy.get(0).get(0).getGroup();
		final ZqGroup secondZqGroup = secondMatrixCopy.get(0).get(0).getGroup();
		checkArgument(firstMatrixCopy.stream().flatMap(Collection::stream).map(ZqElement::getGroup).allMatch(firstZqGroup::equals),
				"All elements of the first matrix must be in the same group.");
		checkArgument(secondMatrixCopy.stream().flatMap(Collection::stream).map(ZqElement::getGroup).allMatch(secondZqGroup::equals),
				"All elements of the second matrix must be in the same group.");
		checkArgument(firstZqGroup.equals(secondZqGroup),
				"The elements of both matrices must be in the same group.");
		checkArgument(y.getGroup().equals(firstZqGroup),
				"The value y must be in the same group as the elements of the matrices.");

		// Computing the d vector.
		final int m = firstMatrixCopy.size() - 1;
		final LinkedList<ZqElement> d = new LinkedList<>();
		final ZqGroup group = y.getGroup();
		for (int k = 0; k <= 2 * m; k++) {
			ZqElement dk = group.getIdentity();
			for (int i = Math.max(0, k - m); i <= m; i++) {
				final int j = (m - k) + i;
				if (j > m) {
					break;
				}
				dk = dk.add(starMap(firstMatrixCopy.get(i), secondMatrixCopy.get(j)));
			}
			d.add(dk);
		}

		return d;
	}

	/**
	 * Define the bilinear map represented by the star operator &#8902; in the specification. All elements must be in the same group. The algorithm
	 * defined by the value {@code y} is the following:
	 * <p>
	 * (a<sub>0</sub>,..., a<sub>n-1</sub>) &#8902; (b<sub>0</sub>,...,b<sub>n-1</sub>) = &sum;<sub>j=0</sub><sup>n-1</sup> a<sub>j</sub> &middot;
	 * b<sub>j</sub> &middot; y<sup>j</sup>
	 *
	 * @param firstVector  a, the first vector.
	 * @param secondVector b, the second vector.
	 * @return The sum &sum;<sub>j=0</sub><sup>n-1</sup> a<sub>j</sub> &middot; b<sub>j</sub> &middot; y<sup>j</sup>
	 */
	ZqElement starMap(final List<ZqElement> firstVector, final List<ZqElement> secondVector) {
		// Null checking and copies.
		checkNotNull(firstVector);
		checkNotNull(secondVector);
		checkArgument(firstVector.stream().allMatch(Objects::nonNull), "The elements of the first vector must not be null.");
		checkArgument(secondVector.stream().allMatch(Objects::nonNull), "The elements of the second vector must not be null.");
		final ImmutableList<ZqElement> firstVectorCopy = ImmutableList.copyOf(firstVector);
		final ImmutableList<ZqElement> secondVectorCopy = ImmutableList.copyOf(secondVector);

		// Dimensions checking.
		checkArgument(firstVectorCopy.size() == secondVectorCopy.size(), "The provided vectors must have the same size.");

		final ZqGroup group = y.getGroup();
		if (firstVectorCopy.isEmpty()) {
			return group.getIdentity();
		}

		// Group checking.
		final ZqGroup firstVectorGroup = firstVectorCopy.get(0).getGroup();
		final ZqGroup secondVectorGroup = secondVectorCopy.get(0).getGroup();
		checkArgument(firstVectorCopy.stream().map(ZqElement::getGroup).allMatch(firstVectorGroup::equals),
				"All elements of the first vector must belong to the same group.");
		checkArgument(secondVectorCopy.stream().map(ZqElement::getGroup).allMatch(secondVectorGroup::equals),
				"All elements of the second vector must belong to the same group.");
		checkArgument(firstVectorGroup.equals(secondVectorGroup),
				"The elements of both vectors must be in the same group.");
		checkArgument(firstVectorGroup.equals(group), "The value y must be in the same group as the vectors elements");

		// StarMap computing.
		final int n = firstVectorCopy.size();
		return IntStream.range(0, n)
				.mapToObj(j -> firstVectorCopy.get(j)
						.multiply(secondVectorCopy.get(j))
						.multiply(y.exponentiate(BigInteger.valueOf(j))))
				.reduce(group.getIdentity(), ZqElement::add);
	}
}
