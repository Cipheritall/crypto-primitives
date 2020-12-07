/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.elgamal;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.List;
import java.util.Objects;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.math.GroupElement;
import ch.post.it.evoting.cryptoprimitives.math.MathematicalGroup;

/**
 * Vector of {@link GroupElement} belonging to the same {@link MathematicalGroup}.
 *
 * <p>Instances of this class are immutable. </p>
 *
 * @param <E> the type of elements this list contains.
 * @param <G> the group type the elements of the list belong to.
 */
public class SameGroupVector<E extends GroupElement<G>, G extends MathematicalGroup<G>> {

	final G group;
	private final ImmutableList<E> elements;

	/**
	 * @param elements the list of elements contained by this vector, which must respect the following:
	 *                 <li>the list must be non-null</li>
	 *                 <li>the list must not be empty</li>
	 *                 <li>the list must not contain any nulls</li>
	 *                 <li>all elements must be from the same {@link MathematicalGroup} </li>
	 */
	public SameGroupVector(List<E> elements) {
		checkNotNull(elements);
		checkArgument(elements.stream().allMatch(Objects::nonNull), "Elements must not contain nulls");
		ImmutableList<E> elementsCopy = ImmutableList.copyOf(elements);

		checkArgument(!elementsCopy.isEmpty(), "Elements must be non empty.");
		checkArgument(elementsCopy.stream().map(GroupElement::getGroup).allMatch(elementsCopy.get(0).getGroup()::equals),
				"All elements must belong to the same group.");

		this.elements = elementsCopy;
		this.group = elementsCopy.get(0).getGroup();
	}

	/**
	 * @return the number of elements this vector contains.
	 */
	public int size() {
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

	public ImmutableList<E> toList() {
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
