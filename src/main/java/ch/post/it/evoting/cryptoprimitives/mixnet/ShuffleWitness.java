/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Objects;

import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.Permutation;

/**
 * Represents a shuffle argument witness, consisting of a permutation &#120587; and a randomness vector &#961;.
 */
class ShuffleWitness {

	private final Permutation permutation;
	private final SameGroupVector<ZqElement, ZqGroup> randomness;

	/**
	 * Instantiates a shuffle witness with the given permutation and randomness vector which must comply with the following:
	 *
	 * <ul>
	 *     <li>be non null and non empty</li>
	 *     <li>have the same size</li>
	 * </ul>
	 *
	 * @param permutation π, the permutation.
	 * @param randomness  ρ, the randomness as a {@link SameGroupVector}.
	 */
	ShuffleWitness(final Permutation permutation, final SameGroupVector<ZqElement, ZqGroup> randomness) {
		checkNotNull(permutation);
		checkNotNull(randomness);

		checkArgument(permutation.getSize() == randomness.size(), "The size of the permutation must be equal to the randomness vector size.");

		this.permutation = permutation;
		this.randomness = randomness;
	}

	Permutation getPermutation() {
		return permutation;
	}

	SameGroupVector<ZqElement, ZqGroup> getRandomness() {
		return randomness;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		ShuffleWitness that = (ShuffleWitness) o;
		return permutation.equals(that.permutation) && randomness.equals(that.randomness);
	}

	@Override
	public int hashCode() {
		return Objects.hash(permutation, randomness);
	}
}