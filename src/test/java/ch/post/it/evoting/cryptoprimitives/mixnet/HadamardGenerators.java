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
