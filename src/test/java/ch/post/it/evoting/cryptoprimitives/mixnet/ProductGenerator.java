/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import java.math.BigInteger;

import ch.post.it.evoting.cryptoprimitives.SameGroupMatrix;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;

class ProductGenerator {

	static ProductWitness genProductWitness(final int n, final int m, final ZqGroupGenerator zqGroupGenerator) {
		SameGroupMatrix<ZqElement, ZqGroup> matrixA = zqGroupGenerator.genRandomZqElementMatrix(n, m);
		SameGroupVector<ZqElement, ZqGroup> exponentsR = zqGroupGenerator.genRandomZqElementVector(m);
		return new ProductWitness(matrixA, exponentsR);
	}

	static ProductStatement getProductStatement(final ProductWitness witness, final CommitmentKey commitmentKey) {
		SameGroupMatrix<ZqElement, ZqGroup> matrixA = witness.getMatrix();
		SameGroupVector<ZqElement, ZqGroup> exponentsR = witness.getExponents();
		SameGroupVector<GqElement, GqGroup> commitmentsA = CommitmentService.getCommitmentMatrix(matrixA, exponentsR, commitmentKey);
		ZqElement one = ZqElement.create(BigInteger.ONE, matrixA.getGroup());
		ZqElement productB = matrixA.stream().reduce(one, ZqElement::multiply);
		return new ProductStatement(commitmentsA, productB);
	}
}
