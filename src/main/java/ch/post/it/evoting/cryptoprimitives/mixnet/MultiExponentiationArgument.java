/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static com.google.common.base.Preconditions.checkNotNull;

import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

/**
 * Value class representing the result of a multi exponentiation proof.
 */
public class MultiExponentiationArgument {
	private GqElement cA0;
	private SameGroupVector<GqElement, GqGroup> cBVector;
	private SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> EVector;
	private SameGroupVector<ZqElement, ZqGroup> aVector;
	private ZqElement r;
	private ZqElement b;
	private ZqElement s;
	private ZqElement tau;
	
	static class Builder {
		private GqElement cA0;
		private SameGroupVector<GqElement, GqGroup> cBVector;
		private SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> EVector;
		private SameGroupVector<ZqElement, ZqGroup> aVector;
		private ZqElement r;
		private ZqElement b;
		private ZqElement s;
		private ZqElement tau;

		Builder(){
			//Intentionally left blank
		}

		Builder withcA0(final GqElement cA0) {
			this.cA0 = cA0;
			return this;
		}

		Builder withcBVector(final SameGroupVector<GqElement, GqGroup> cBVector) {
			this.cBVector = cBVector;
			return this;
		}

		Builder withEVector(final SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> EVector) {
			this.EVector = EVector;
			return this;
		}

		Builder withaVector(final SameGroupVector<ZqElement, ZqGroup> aVector) {
			this.aVector = aVector;
			return this;
		}

		Builder withr(final ZqElement r) {
			this.r = r;
			return this;
		}

		Builder withb(final ZqElement b) {
			this.b = b;
			return this;
		}

		Builder withs(final ZqElement s) {
			this.s = s;
			return this;
		}

		Builder withtau(final ZqElement tau) {
			this.tau = tau;
			return this;
		}

		MultiExponentiationArgument build() {
			MultiExponentiationArgument argument = new MultiExponentiationArgument();
			argument.cA0 = checkNotNull(this.cA0);
			argument.cBVector = checkNotNull(this.cBVector);
			argument.EVector = checkNotNull(this.EVector);
			argument.aVector = checkNotNull(this.aVector);
			argument.r = checkNotNull(this.r);
			argument.b = checkNotNull(this.b);
			argument.s = checkNotNull(this.s);
			argument.tau = checkNotNull(this.tau);
			return argument;
		}
	}
}
