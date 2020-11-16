/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.elgamal;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.List;
import java.util.Objects;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.math.StreamlinedGroupElement;
import ch.post.it.evoting.cryptoprimitives.math.StreamlinedMathematicalGroup;

/**
 * Vector of {@link StreamlinedGroupElement} belonging to the same {@link StreamlinedMathematicalGroup}.
 *
 * <p>Instances of this class are immutable. </p>
 *
 * @param <E> the type of elements this actor contains.
 * @param <G> the group type the elements of the vector belong to.
 */
public class SameGroupVector<E extends StreamlinedGroupElement<G>, G extends StreamlinedMathematicalGroup<G>> {

	final G group;
	private final ImmutableList<E> elements;

	/**
	 * @param elements the list of elements contained by this actor, which must respect the following:
	 *                 <li>the list must be non-null</li>
	 *                 <li>the list must not be empty</li>
	 *                 <li>the list must not contain any nulls</li>
	 *                 <li>all elements must be from the same {@link StreamlinedMathematicalGroup} </li>
	 */
	SameGroupVector(List<E> elements) {
		checkNotNull(elements);
		checkArgument(!elements.isEmpty(), "Elements must be non empty.");
		checkArgument(elements.stream().allMatch(Objects::nonNull), "Elements must not contain nulls");
		checkArgument(elements.stream().map(StreamlinedGroupElement::getGroup).allMatch(elements.get(0).getGroup()::equals),
				"All elements must belong to the same group.");

		this.elements = ImmutableList.copyOf(elements);
		this.group = elements.get(0).getGroup();
	}

	/**
	 * @return the number of elements this vector contains.
	 */
	public int length() {
		return elements.size();
	}

	/**
	 * @return the ith element.
	 */
	public E get(int i) {
		checkArgument(i >= 0);
		checkArgument(i < elements.size());
		return elements.get(i);
	}

	/**
	 * @return the group all elements belong to.
	 */
	public G getGroup() {
		return this.group;
	}

	ImmutableList<E> toList() {
		return this.elements;
	}

	@Override
	public String toString() {
		return "SameGroupVector{" + "elements=" + elements + '}';
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		SameGroupVector<?, ?> that = (SameGroupVector<?, ?>) o;
		return elements.equals(that.elements);
	}

	@Override
	public int hashCode() {
		return Objects.hash(elements);
	}
}
