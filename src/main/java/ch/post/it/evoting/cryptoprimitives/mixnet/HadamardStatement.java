package ch.post.it.evoting.cryptoprimitives.mixnet;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;

class HadamardStatement {

	private final SameGroupVector<GqElement, GqGroup> commitmentsA;
	private final GqElement commitmentB;

	HadamardStatement(final SameGroupVector<GqElement, GqGroup> commitmentsA, final GqElement commitmentB) {
		checkNotNull(commitmentsA);
		checkNotNull(commitmentB);

		this.commitmentsA = commitmentsA;
		this.commitmentB = commitmentB;

		checkArgument(this.commitmentsA.getGroup().equals(this.commitmentB.getGroup()),
				"The commitments A and commitment b must have the same group.");
	}

	SameGroupVector<GqElement, GqGroup> getCommitmentsA() {
		return commitmentsA;
	}

	GqElement getCommitmentB() {
		return commitmentB;
	}
}
