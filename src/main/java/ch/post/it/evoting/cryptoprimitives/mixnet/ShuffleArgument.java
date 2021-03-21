/*
 * Copyright 2021 Post CH Ltd
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
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static ch.post.it.evoting.cryptoprimitives.Validations.allEqual;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableList;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;

/**
 * Value class containing the result of a shuffle argument proof.
 */
public class ShuffleArgument implements HashableList {

	private GroupVector<GqElement, GqGroup> cA;
	private GroupVector<GqElement, GqGroup> cB;
	private ProductArgument productArgument;
	private MultiExponentiationArgument multiExponentiationArgument;

	private int m;
	private int n;
	private int l;
	private GqGroup group;

	private ShuffleArgument() {
		// Intentionally left blank.
	}

	GroupVector<GqElement, GqGroup> getcA() {
		return cA;
	}

	GroupVector<GqElement, GqGroup> getcB() {
		return cB;
	}

	ProductArgument getProductArgument() {
		return productArgument;
	}

	MultiExponentiationArgument getMultiExponentiationArgument() {
		return multiExponentiationArgument;
	}

	int getM() {
		return m;
	}

	int getN() {
		return n;
	}

	int getL() {
		return l;
	}

	GqGroup getGroup() {
		return group;
	}

	@Override
	public boolean equals(final Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		final ShuffleArgument that = (ShuffleArgument) o;
		return cA.equals(that.cA) && cB.equals(that.cB) && productArgument.equals(that.productArgument) && multiExponentiationArgument
				.equals(that.multiExponentiationArgument);
	}

	@Override
	public int hashCode() {
		return Objects.hash(cA, cB, productArgument, multiExponentiationArgument);
	}

	@Override
	public ImmutableList<? extends Hashable> toHashableForm() {
		return ImmutableList.of(cA, cB, productArgument, multiExponentiationArgument);
	}

	public static class Builder {

		private GroupVector<GqElement, GqGroup> cA;
		private GroupVector<GqElement, GqGroup> cB;
		private ProductArgument productArgument;
		private MultiExponentiationArgument multiExponentiationArgument;

		public Builder withCA(final GroupVector<GqElement, GqGroup> cA) {
			this.cA = cA;
			return this;
		}

		public Builder withCB(final GroupVector<GqElement, GqGroup> cB) {
			this.cB = cB;
			return this;
		}

		public Builder withProductArgument(final ProductArgument productArgument) {
			this.productArgument = productArgument;
			return this;
		}

		public Builder withMultiExponentiationArgument(final MultiExponentiationArgument multiExponentiationArgument) {
			this.multiExponentiationArgument = multiExponentiationArgument;
			return this;
		}

		/**
		 * Builds the {@link ShuffleArgument}. Upon calling this method, all fields must have been set to non null values.
		 * <p>
		 * Additionally, the fields must comply with the following:
		 * <ul>
		 *     <li>cA, cB, the product and multi exponentiation arguments must belong to the same group</li>
		 *     <li>cA, cB, the product and multi exponentiation arguments must have identical dimension m</li>
		 *     <li>the product and multi exponentiation arguments must have identical dimension n</li>
		 * </ul>
		 *
		 * @return A valid Shuffle Argument.
		 */
		public ShuffleArgument build() {
			// Null checking.
			checkNotNull(this.cA);
			checkNotNull(this.cB);
			checkNotNull(this.productArgument);
			checkNotNull(this.multiExponentiationArgument);

			// Cross group checking.
			final List<GqGroup> gqGroups = Arrays
					.asList(this.cA.getGroup(), this.cB.getGroup(), this.productArgument.getGroup(), this.multiExponentiationArgument.getGroup());
			checkArgument(allEqual(gqGroups.stream(), g -> g),
					"The commitments cA, cB, the product and the multi exponentiation arguments must belong to the same group.");

			// Cross dimensions checking.
			final List<Integer> mDimensions = Arrays
					.asList(this.cA.size(), this.cB.size(), this.productArgument.getM(), this.multiExponentiationArgument.getM());
			checkArgument(allEqual(mDimensions.stream(), d -> d),
					"The commitments cA, cB and the product and multi exponentiation arguments must have the same dimension m.");

			checkArgument(this.productArgument.getN() == this.multiExponentiationArgument.getN(),
					"The product and multi exponentiation arguments must have the same dimension n.");

			// Build the argument.
			final ShuffleArgument shuffleArgument = new ShuffleArgument();
			shuffleArgument.cA = this.cA;
			shuffleArgument.cB = this.cB;
			shuffleArgument.productArgument = this.productArgument;
			shuffleArgument.multiExponentiationArgument = this.multiExponentiationArgument;

			shuffleArgument.m = productArgument.getM();
			shuffleArgument.n = productArgument.getN();
			shuffleArgument.l = multiExponentiationArgument.getL();
			shuffleArgument.group = productArgument.getGroup();

			return shuffleArgument;
		}
	}
}
