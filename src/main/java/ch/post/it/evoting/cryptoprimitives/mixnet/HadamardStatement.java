/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;

class HadamardStatement {

	private final SameGroupVector<GqElement, GqGroup> commitmentsA;
	private final GqElement commitmentB;
	private final GqGroup group;
	private final int m;

	/**
	 * Constructs a {@code HadamardStatement} object.
	 * <p>
	 * Both inputs must comply with the following:
	 * <ul>
	 *     <li>be non null</li>
	 *     <li>belong to the same group</li>
	 * </ul>
	 *
	 * @param commitmentsA c<sub>A</sub>, the vectors of commitments to a matrix A
	 * @param commitmentB  c<sub>b</sub>, the commitment to a vector b.
	 */
	HadamardStatement(final SameGroupVector<GqElement, GqGroup> commitmentsA, final GqElement commitmentB) {
		checkNotNull(commitmentsA);
		checkNotNull(commitmentB);

		this.commitmentsA = commitmentsA;
		this.commitmentB = commitmentB;
		this.group = commitmentsA.getGroup();
		this.m = commitmentsA.size();

		checkArgument(this.commitmentsA.getGroup().equals(this.commitmentB.getGroup()),
				"The commitments A and commitment b must have the same group.");
	}

	SameGroupVector<GqElement, GqGroup> getCommitmentsA() {
		return commitmentsA;
	}

	GqElement getCommitmentB() {
		return commitmentB;
	}

	GqGroup getGroup() {
		return group;
	}

	int getM() {
		return m;
	}
}
