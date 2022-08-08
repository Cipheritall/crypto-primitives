/*
 * Copyright 2022 Post CH Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ch.post.it.evoting.cryptoprimitives.math;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Objects;

import ch.post.it.evoting.cryptoprimitives.internal.math.PrimesInternal;
import ch.post.it.evoting.cryptoprimitives.math.GqElement.GqElementFactory;

/**
 * Defines a Gq group element that is a small prime and different from the group generator.
 *
 * <p>Instances of this class are immutable.
 */
public final class PrimeGqElement extends MultiplicativeGroupElement {

	private final GqElement delegate;

	// Private constructor without input validation. Used only for operations that provide a mathematical guarantee that the element is a prime within
	// the group and is different from the group generator.
	private PrimeGqElement(final int value, final GqGroup group) {
		super(BigInteger.valueOf(value), group);
		this.delegate = GqElementFactory.fromValue(BigInteger.valueOf(value), group);
	}

	@Override
	public GqElement multiply(final MultiplicativeGroupElement other) {
		return delegate.multiply(other);
	}

	@Override
	public GqElement exponentiate(final ZqElement exponent) {
		return delegate.exponentiate(exponent);
	}

	public Integer getValueAsInt() {
		return this.delegate.getValue().intValueExact();
	}

	@Override
	public boolean equals(final Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		if (!super.equals(o)) {
			return false;
		}
		final PrimeGqElement that = (PrimeGqElement) o;
		return delegate.equals(that.delegate);
	}

	@Override
	public int hashCode() {
		return Objects.hash(super.hashCode(), delegate);
	}

	public static class PrimeGqElementFactory {

		private PrimeGqElementFactory() {
			// empty on purpose
		}

		/**
		 * Creates a {@code PrimeGqElement}.
		 * <p>
		 * The {@code value} and {@code desiredNumberOfPrimes} parameters must comply with the following:
		 * <ul>
		 *     <li>must be non-null.</li>
		 *     <li>the value must be an element of the group.</li>
		 *     <li>the value must be a small prime.</li>
		 *     <li>the value must be different from the group generator.</li>
		 * </ul>
		 *
		 * @param value the value of the element. Must be not-null, a prime element of the group, and different from the group generator.
		 * @param group the {@link GqGroup} to which this element belongs. Must be non-null.
		 * @return a new PrimeGqElement with the specified value in the given group.
		 */
		public static PrimeGqElement fromValue(final int value, final GqGroup group) {
			checkArgument(PrimesInternal.isSmallPrime(value),
					"Cannot create a PrimeGqElement with given value as it is not a prime element. [value: %s]", value);
			checkArgument(BigInteger.valueOf(value).compareTo(group.getGenerator().getValue()) != 0,
					"Cannot create a PrimeGqElement with given value as it is the generator of the group. [value :%, group: %s]", value, group);

			return new PrimeGqElement(value, group);
		}

		/**
		 * Collects the desired number of primes belonging to a group into a vector.
		 * <p>
		 * The {@code gqGroup} and {@code desiredNumberOfPrimes} parameters must comply with the following:
		 * <ul>
		 *     <li>must be non-null.</li>
		 *     <li>the group generator must be in the range [2, 4].</li>
		 *     <li>the desired number of primes must be smaller than q - 4, i.e. the number of elements in the group by at least 4.</li>
		 *     <li>the desired number of primes must be in the range (0, 10000).</li>
		 * </ul>
		 *
		 * @param gqGroup               the group of which to get the small prime group members. Must be non-null.
		 * @param desiredNumberOfPrimes r, the desired number of prime group members. Must be strictly positive.
		 * @return a vector of prime group members of the desired length.
		 * @throws IllegalStateException if the group does not contain the desired number of prime group members.
		 */
		@SuppressWarnings("java:S117")
		public static GroupVector<PrimeGqElement, GqGroup> getSmallPrimeGroupMembers(final GqGroup gqGroup, final int desiredNumberOfPrimes) {
			checkNotNull(gqGroup);

			final int r = desiredNumberOfPrimes;
			final BigInteger g = gqGroup.getGenerator().value;

			checkArgument(r > 0, "The desired number of primes must be strictly positive");
			checkArgument(BigInteger.valueOf(2).compareTo(g) <= 0 && g.compareTo(BigInteger.valueOf(4)) <= 0, "g must be 2, 3, or 4");
			checkArgument(BigInteger.valueOf(r).compareTo(gqGroup.getQ().subtract(BigInteger.valueOf(4))) <= 0,
					"The desired number of primes must be smaller than the number of elements in the GqGroup by at least 4");
			checkArgument(r < 10000, "The desired number of primes must be strictly smaller than 10000");

			BigInteger current = BigInteger.valueOf(5);
			final ArrayList<PrimeGqElement> p_vector = new ArrayList<>(r);
			int count = 0;
			while (count < r && current.compareTo(gqGroup.getP()) < 0 && current.compareTo(BigInteger.valueOf(Integer.MAX_VALUE)) < 0) {
				if (gqGroup.isGroupMember(current) && PrimesInternal.isSmallPrime(current.intValueExact())
						&& !current.equals(gqGroup.getGenerator().value)) {
					p_vector.add(new PrimeGqElement(current.intValueExact(), gqGroup));
					count++;
				}
				current = current.add(BigInteger.valueOf(2));
			}
			checkState(count == r, "The number of primes found does not correspond to the number of desired primes.");

			return GroupVector.from(p_vector);
		}

	}
}
