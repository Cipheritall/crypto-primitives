/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.List;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Streams;

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
public class SameGroupVector<E extends HasGroup<G>, G extends MathematicalGroup<G>> {

	private final G group;
	private final ImmutableList<E> elements;

	/**
	 * @param elements the list of elements contained by this vector, which must respect the following:
	 *                 <li>the list must be non-null</li>
	 *                 <li>the list must not contain any nulls</li>
	 *                 <li>all elements must be from the same {@link MathematicalGroup} </li>
	 */
	public SameGroupVector(List<E> elements) {
		//Check null values
		checkNotNull(elements);
		checkArgument(elements.stream().allMatch(Objects::nonNull), "Elements must not contain nulls");

		//Immutable copy
		ImmutableList<E> elementsCopy = ImmutableList.copyOf(elements);

		//Check same group
		checkArgument(Validations.allEqual(elementsCopy.stream(), HasGroup::getGroup), "All elements must belong to the same group.");

		this.group = elementsCopy.isEmpty() ? null : elementsCopy.get(0).getGroup();
		this.elements = elementsCopy;
	}

	/**
	 * @return the number of elements this vector contains.
	 */
	public int size() {
		return elements.size();
	}

	public boolean isEmpty() {
		return elements.isEmpty();
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
	 * @throws IllegalStateException if the vector is empty.
	 */
	public G getGroup() {
		if (this.isEmpty()) {
			throw new IllegalStateException("An empty SameGroupVector does not have a group.");
		} else {
			return this.group;
		}
	}

	/**
	 * @return an ordered sequential stream of the vector's elements.
	 */
	public Stream<E> stream() {
		return this.elements.stream();
	}

	/**
	 * Append a new element to this vector. Returns a new SameGroupVector.
	 *
	 * @param element The element to append. Must be non null and from the same group.
	 * @return A new SameGroupVector with the appended {@code element}.
	 */
	public SameGroupVector<E, G> append(final E element) {
		checkNotNull(element);
		checkArgument(element.getGroup().equals(this.group), "The element to prepend must be in the same group.");

		final List<E> newVector = Streams.concat(this.stream(), Stream.of(element)).collect(Collectors.toList());
		return new SameGroupVector<>(newVector);
	}

	/**
	 * Prepend a new element to this vector. Returns a new SameGroupVector.
	 *
	 * @param element The element to prepend. Must be non null and from the same group.
	 * @return A new SameGroupVector with the prepended {@code element}.
	 */
	public SameGroupVector<E, G> prepend(final E element) {
		checkNotNull(element);
		checkArgument(element.getGroup().equals(this.group), "The element to prepend must be in the same group.");

		final List<E> newVector = Streams.concat(Stream.of(element), this.stream()).collect(Collectors.toList());
		return new SameGroupVector<>(newVector);
	}

	/**
	 * Validate that a property holds for all elements.
	 *
	 * @param property to check all elements against.
	 * @return true if the vector is empty or all elements are equal under this property. False otherwise.
	 */
	public boolean allEqual(Function<? super E, ?> property) {
		return Validations.allEqual(this.elements.stream(), property);
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
