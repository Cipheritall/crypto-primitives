/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static ch.post.it.evoting.cryptoprimitives.Validations.allEqual;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;

/**
 * Value class containing the result of a shuffle argument proof.
 */
class ShuffleArgument {

	private SameGroupVector<GqElement, GqGroup> cA;
	private SameGroupVector<GqElement, GqGroup> cB;
	private ProductArgument productArgument;
	private MultiExponentiationArgument multiExponentiationArgument;

	private int m;
	private int n;
	private GqGroup group;

	private ShuffleArgument() {
		// Intentionally left blank.
	}

	SameGroupVector<GqElement, GqGroup> getcA() {
		return cA;
	}

	SameGroupVector<GqElement, GqGroup> getcB() {
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

	GqGroup getGroup() {
		return group;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		ShuffleArgument that = (ShuffleArgument) o;
		return cA.equals(that.cA) && cB.equals(that.cB) && productArgument.equals(that.productArgument) && multiExponentiationArgument
				.equals(that.multiExponentiationArgument);
	}

	@Override
	public int hashCode() {
		return Objects.hash(cA, cB, productArgument, multiExponentiationArgument);
	}

	static class Builder {

		private SameGroupVector<GqElement, GqGroup> cA;
		private SameGroupVector<GqElement, GqGroup> cB;
		private ProductArgument productArgument;
		private MultiExponentiationArgument multiExponentiationArgument;

		Builder withCA(final SameGroupVector<GqElement, GqGroup> cA) {
			this.cA = cA;
			return this;
		}

		Builder withCB(final SameGroupVector<GqElement, GqGroup> cB) {
			this.cB = cB;
			return this;
		}

		Builder withProductArgument(final ProductArgument productArgument) {
			this.productArgument = productArgument;
			return this;
		}

		Builder withMultiExponentiationArgument(final MultiExponentiationArgument multiExponentiationArgument) {
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
		ShuffleArgument build() {
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
			shuffleArgument.group = productArgument.getGroup();

			return shuffleArgument;
		}
	}
}
