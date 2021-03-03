/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.test.tools.generator;

import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ch.post.it.evoting.cryptoprimitives.GroupVectorElement;
import ch.post.it.evoting.cryptoprimitives.math.MathematicalGroup;

public class GroupVectorElementGenerator {

	/**
	 * Generate a list of {@link GroupVectorElement} elements.
	 *
	 * @param numElements the number of elements to generate
	 * @param s the supplier to create a single element
	 * @param <E> the element type
	 * @param <G> the element group
	 * @return a list of elements
	 */
	public static <E extends GroupVectorElement<G>, G extends MathematicalGroup<G>> List<E> generateElementList(final int numElements, Supplier<E> s) {
		return Stream.generate(s).limit(numElements).collect(Collectors.toList());
	}

	/**
	 * Generate a matrix of {@link GroupVectorElement} elements.
	 *
	 * @param numRows the number of rows to generate
	 * @param numColumns the number of columns to generate
	 * @param s the supplier of a single element
	 * @param <E> the element type
	 * @param <G> the element group type
	 * @return a matrix of elements.
	 */
	public static <E extends GroupVectorElement<G>, G extends MathematicalGroup<G>>
	List<List<E>> generateElementMatrix(final int numRows, final int numColumns, Supplier<E> s) {
		return Stream.generate(() -> generateElementList(numColumns, s)).limit(numRows).collect(Collectors.toList());
	}
}
