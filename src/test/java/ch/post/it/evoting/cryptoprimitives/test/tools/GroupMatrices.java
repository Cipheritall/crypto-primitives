package ch.post.it.evoting.cryptoprimitives.test.tools;

import static java.util.stream.Collectors.toList;

import java.util.ArrayList;
import java.util.List;

import ch.post.it.evoting.cryptoprimitives.SameGroupMatrix;
import ch.post.it.evoting.cryptoprimitives.GroupVectorElement;
import ch.post.it.evoting.cryptoprimitives.Hashable;
import ch.post.it.evoting.cryptoprimitives.math.MathematicalGroup;

public class GroupMatrices {

	/**
	 * Return a new SameGroupMatrix copy with the element i replaced with the provided element.
	 * @param matrix the matrix to modify
	 * @param i the row of the element to set
	 * @param j the column of the element to set
	 * @param element the value to set it to
	 * @param <E> the type of elements in this vector
	 * @param <G> the group of these elements
	 * @return a new SameGroupMatrix with the (i, j) element replaced.
	 */
	public static <E extends GroupVectorElement<G> & Hashable, G extends MathematicalGroup<G>>
	SameGroupMatrix<E, G> set(SameGroupMatrix<E, G> matrix, int i, int j, E element) {
		List<List<E>> modifiedElements = matrix.rowStream().map(ArrayList::new).collect(toList());
		modifiedElements.get(i).set(j, element);
		return SameGroupMatrix.fromRows(modifiedElements);
	}
}
