/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import ch.post.it.evoting.cryptoprimitives.SameGroupMatrix;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;

class MultiExponentiationWitnessGenerator {
	private final ZqGroupGenerator zqGroupGenerator;

	MultiExponentiationWitnessGenerator(ZqGroup group) {
		this.zqGroupGenerator = new ZqGroupGenerator(group);
	}

	MultiExponentiationWitness genRandomWitness(int n, int m) {
		SameGroupMatrix<ZqElement, ZqGroup> matrixA = zqGroupGenerator.genRandomZqElementMatrix(n, m);
		SameGroupVector<ZqElement, ZqGroup> exponentsR = zqGroupGenerator.genRandomZqElementVector(m);
		ZqElement exponentsRho = zqGroupGenerator.genRandomZqElementMember();
		return new MultiExponentiationWitness(matrixA, exponentsR, exponentsRho);
	}
}
