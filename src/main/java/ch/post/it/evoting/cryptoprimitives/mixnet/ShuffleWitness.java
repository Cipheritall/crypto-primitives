/*
 * Copyright 2022 Post CH Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Objects;

import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

/**
 * Represents a shuffle argument witness, consisting of a permutation &#120587; and a randomness vector &#961;.
 *
 * <p>Instances of this class are immutable.</p>
 */
@SuppressWarnings("java:S100")
public final class ShuffleWitness {

	private final Permutation pi;
	private final GroupVector<ZqElement, ZqGroup> rho;

	/**
	 * Instantiates a shuffle witness with the given permutation and randomness vector which must comply with the following:
	 *
	 * <ul>
	 *     <li>be non null and non empty</li>
	 *     <li>have the same size</li>
	 * </ul>
	 *
	 * @param pi π, the permutation.
	 * @param rho  ρ, the randomness as a {@link GroupVector}.
	 */
	public ShuffleWitness(final Permutation pi, final GroupVector<ZqElement, ZqGroup> rho) {
		checkNotNull(pi);
		checkNotNull(rho);

		checkArgument(pi.size() == rho.size(), "The size of the permutation must be equal to the randomness vector size.");

		this.pi = pi;
		this.rho = rho;
	}

	public Permutation get_pi() {
		return pi;
	}

	public GroupVector<ZqElement, ZqGroup> get_rho() {
		return rho;
	}

	@Override
	public boolean equals(final Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		final ShuffleWitness that = (ShuffleWitness) o;
		return pi.equals(that.pi) && rho.equals(that.rho);
	}

	@Override
	public int hashCode() {
		return Objects.hash(pi, rho);
	}
}
