package ch.post.it.evoting.cryptoprimitives.zeroknowledgeproofs;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;

public class ExponentiationProofService {

	private ExponentiationProofService() {

	}

	/**
	 * Computes an image of a 𝜙-function for exponentiation given a preimage and bases g<sub>0</sub>, ..., g<sub>n-1</sub>.
	 *
	 * @param preimage x ∈ Z<sub>q</sub>. Not null.
	 * @param bases    (g<sub>0</sub>, ..., g<sub>n-1</sub>) ∈ G<sub>q</sub><sup>n</sup>. Not null and not empty.
	 * @return an image (y<sub>0</sub>, ..., y<sub>n-1</sub>) ∈ G<sub>q</sub><sup>n</sup>
	 */
	public static GroupVector<GqElement, GqGroup> computePhiExponentiation(final ZqElement preimage, final GroupVector<GqElement, GqGroup> bases) {
		checkNotNull(preimage);
		checkNotNull(bases);

		checkArgument(!bases.isEmpty(), "The vector of bases must contain at least 1 element.");
		checkArgument(preimage.getGroup().hasSameOrderAs(bases.getGroup()), "The preimage and the bases must have the same group order.");

		final ZqElement x = preimage;
		final GroupVector<GqElement, GqGroup> g = bases;

		return g.stream().map(g_i -> g_i.exponentiate(x)).collect(GroupVector.toGroupVector());
	}
}
