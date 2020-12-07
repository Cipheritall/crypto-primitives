/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.MathematicalGroup;

/**
 * Represents a public key of {@link GqElement}s that is used for the calculation of a commitment.
 * Instances of this class are immutable.
 *
 * <p>A commitment key is of the form (h, g<sub>1</sub>, ..., g<sub>k</sub>)</p>
 */
class CommitmentKey {

	private final GqGroup group;
	private final GqElement h;
	private final ImmutableList<GqElement> gElements;

	/**
	 * Creates a {@link CommitmentKey} object.
	 *
	 * @param h			the h element of this commitment key, which must respect the following:
	 *                  	<li>h must be non-null</li>
	 *                 		<li>h must be different from 1</li>
	 *	                    <li>h must be different from the generator of the group it belongs to</li></p>
	 * @param gElements the list of g elements contained by this commitment key, which must respect the following:
	 *                 		<li>the list must be non-null</li>
	 *                 		<li>the list must contain at least one element</li>
	 *                 		<li>the list must not contain any nulls</li>
	 *                 		<li>all elements must be from the same {@link MathematicalGroup} as h</li>
	 *                 		<li>no element must be equal to 1</li>
	 *	                    <li>no element must be equal to the generator of the group they belong to</li></p>
	 */
	CommitmentKey(GqElement h, List<GqElement> gElements) {
		checkNotNull(h);
		checkArgument(!h.equals(h.getGroup().getIdentity()), "h cannot be 1");
		checkArgument(!h.equals(h.getGroup().getGenerator()), "h cannot be equal to the group generator");
		this.h = h;
		this.group = h.getGroup();

		checkNotNull(gElements);
		checkArgument(gElements.stream().noneMatch(Objects::isNull), "A commitment key cannot contain null elements");
		this.gElements = ImmutableList.copyOf(gElements);

		checkArgument(!this.gElements.isEmpty(), "No g element provided");
		checkArgument(this.gElements.stream().map(GqElement::getGroup).allMatch(h.getGroup()::equals),
				"All g elements must have the same group as h");
		checkArgument(this.gElements.stream().noneMatch(element -> element.equals(group.getIdentity())),
				"A commitment key cannot contain a 1 valued element.");
		checkArgument(this.gElements.stream().noneMatch(element -> element.equals(group.getGenerator())),
				"A commitment key cannot contain an element value equal to the group generator.");
	}

	/**
	 * @return the group the elements of the commitment key belong to
	 */
	GqGroup getGroup() {
		return this.group;
	}

	/**
	 * @return the number of g elements
	 */
	int size() {
		return gElements.size();
	}

	/**
	 * @return h
	 */
	GqElement getH() {
		return h;
	}

	/**
	 * @return the g elements
	 */
	List<GqElement> getGElements() {
		return gElements;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}

		final CommitmentKey that = (CommitmentKey) o;

		return h.equals(that.h) && gElements.equals(that.gElements);
	}

	@Override
	public int hashCode() {
		return Objects.hash(h, gElements);
	}

	@Override
	public String toString() {
		List<String> simpleGElements = gElements.stream().map(GqElement::getValue).map(BigInteger::toString).collect(Collectors.toList());
		return "CommitmentKey{" + "h=" + h + ", g elements=" + simpleGElements + '}';
	}
}
