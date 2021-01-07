/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static com.google.common.base.Preconditions.checkNotNull;

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

		ShuffleArgument build() {
			final ShuffleArgument shuffleArgument = new ShuffleArgument();
			shuffleArgument.cA = checkNotNull(this.cA);
			shuffleArgument.cB = checkNotNull(this.cB);
			shuffleArgument.productArgument = checkNotNull(this.productArgument);
			shuffleArgument.multiExponentiationArgument = checkNotNull(this.multiExponentiationArgument);

			return shuffleArgument;
		}
	}
}
