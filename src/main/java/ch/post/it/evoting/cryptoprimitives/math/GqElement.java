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

import java.math.BigInteger;

import ch.post.it.evoting.cryptoprimitives.internal.math.BigIntegerOperationsService;

/**
 * Defines a Gq group element, ie elements of the quadratic residue group of order q and mod p.
 *
 * <p>Instances of this class are immutable.
 */
@SuppressWarnings("java:S117")
public final class GqElement extends MultiplicativeGroupElement {

	// Private constructor without input validation. Used only for operations that provide a mathematical guarantee that the element is within the
	// group (such as multiplying two elements of the same group).
	private GqElement(final BigInteger value, final GqGroup group) {
		super(value, group);
	}

	@Override
	public GqElement multiply(final MultiplicativeGroupElement other) {
		checkNotNull(other);
		checkArgument(this.group.equals(other.group));

		final BigInteger resultValue = BigIntegerOperationsService.modMultiply(value, other.getValue(), group.getP());
		return new GqElement(resultValue, this.group);
	}

	@Override
	public GqElement exponentiate(final ZqElement exponent) {
		checkNotNull(exponent);
		checkArgument(isOfSameOrderGroup(exponent));

		final BigInteger valueExponentiated = BigIntegerOperationsService.modExponentiate(value, exponent.getValue(), this.group.getP());
		return new GqElement(valueExponentiated, this.group);
	}

	private boolean isOfSameOrderGroup(final ZqElement exponent) {
		return this.group.hasSameOrderAs(exponent.getGroup());
	}

	public GqElement invert() {
		final BigInteger invertedValue = BigIntegerOperationsService.modInvert(this.getValue(), this.group.getP());
		return new GqElement(invertedValue, this.group);
	}

	@Override
	public String toString() {
		return "GqElement [value=" + value + "," + group.toString() + "]";
	}

	public static class GqElementFactory {

		private GqElementFactory() {
			// empty on purpose
		}

		/**
		 * Creates a {@code GqElement}. The specified value should be an element of the group.
		 *
		 * @param value the value of the element. Must not be null and must be an element of the group.
		 * @param group the {@link GqGroup} to which this element belongs. Must be non-null.
		 * @return a new GqElement with the specified value in the given group
		 */
		public static GqElement fromValue(final BigInteger value, final GqGroup group) {
			checkNotNull(value);
			checkNotNull(group);
			checkArgument(group.isGroupMember(value), "Cannot create a GroupElement with value %s as it is not an element of group %s", value, group);

			return new GqElement(value, group);
		}

		/**
		 * Creates a GqElement from a BigInteger by squaring it modulo p.
		 *
		 * @param element the BigInteger to be squared. Must be non-null.
		 * @param group   the GqGroup in which to get the new GqElement. Must be non-null.
		 * @return the squared element modulo p.
		 * @throws NullPointerException     if any of the arguments is null
		 * @throws IllegalArgumentException if the element is 0 or smaller or bigger than the group's order
		 */
		public static GqElement fromSquareRoot(final BigInteger element, final GqGroup group) {
			checkNotNull(element);
			checkNotNull(group);

			checkArgument(element.compareTo(BigInteger.ZERO) > 0, "The element must be strictly greater than 0");
			checkArgument(element.compareTo(group.getQ()) < 0, "The element must be smaller than the group's order");

			final BigInteger y = BigIntegerOperationsService.modExponentiate(element, BigInteger.valueOf(2), group.getP());
			return new GqElement(y, group);
		}

	}
}
