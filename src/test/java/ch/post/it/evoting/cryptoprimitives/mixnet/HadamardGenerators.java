/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static ch.post.it.evoting.cryptoprimitives.SameGroupVector.toSameGroupVector;

import java.math.BigInteger;
import java.util.stream.IntStream;

import ch.post.it.evoting.cryptoprimitives.SameGroupMatrix;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;

class HadamardGenerators {

	static HadamardWitness generateHadamardWitness(final int n, final int m, final ZqGroup zqGroup) {
		ZqElement one = ZqElement.create(BigInteger.ONE, zqGroup);

		// Generate the Hadamard witness
		ZqGroupGenerator zqGenerator = new ZqGroupGenerator(zqGroup);
		SameGroupMatrix<ZqElement, ZqGroup> matrix = zqGenerator.genRandomZqElementMatrix(n, m);
		SameGroupVector<ZqElement, ZqGroup> vector = IntStream.range(0, n)
				.mapToObj(i -> matrix.getRow(i).stream().reduce(one, ZqElement::multiply))
				.collect(toSameGroupVector());
		SameGroupVector<ZqElement, ZqGroup> exponents = zqGenerator.genRandomZqElementVector(m);
		ZqElement randomness = zqGenerator.genRandomZqElementMember();

		return new HadamardWitness(matrix, vector, exponents, randomness);
	}

	static HadamardStatement generateHadamardStatement(HadamardWitness witness, CommitmentKey commitmentKey) {
		// Generate the Hadamard statement
		SameGroupVector<GqElement, GqGroup> commitmentsA = CommitmentService
				.getCommitmentMatrix(witness.getMatrixA(), witness.getExponentsR(), commitmentKey);
		GqElement commitmentB = CommitmentService.getCommitment(witness.getVectorB(), witness.getExponentS(), commitmentKey);
		return new HadamardStatement(commitmentsA, commitmentB);
	}
}
