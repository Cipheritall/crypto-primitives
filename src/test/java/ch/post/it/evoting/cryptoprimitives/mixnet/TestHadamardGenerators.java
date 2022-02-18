/*
 * Copyright 2022 Post CH Ltd
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

import static ch.post.it.evoting.cryptoprimitives.math.GroupVector.toGroupVector;

import java.math.BigInteger;
import java.util.stream.IntStream;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupMatrix;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;

class TestHadamardGenerators {

	static HadamardWitness generateHadamardWitness(final int n, final int m, final ZqGroup zqGroup) {
		final ZqElement one = ZqElement.create(BigInteger.ONE, zqGroup);

		// Generate the Hadamard witness
		final ZqGroupGenerator zqGenerator = new ZqGroupGenerator(zqGroup);
		final GroupMatrix<ZqElement, ZqGroup> matrix = zqGenerator.genRandomZqElementMatrix(n, m);
		final GroupVector<ZqElement, ZqGroup> vector = IntStream.range(0, n)
				.mapToObj(i -> matrix.getRow(i).stream().reduce(one, ZqElement::multiply))
				.collect(toGroupVector());
		final GroupVector<ZqElement, ZqGroup> exponents = zqGenerator.genRandomZqElementVector(m);
		final ZqElement randomness = zqGenerator.genRandomZqElementMember();

		return new HadamardWitness(matrix, vector, exponents, randomness);
	}

	static HadamardStatement generateHadamardStatement(final HadamardWitness witness, final CommitmentKey commitmentKey) {
		// Generate the Hadamard statement
		final GroupVector<GqElement, GqGroup> commitmentsA = CommitmentService
				.getCommitmentMatrix(witness.get_A(), witness.get_r(), commitmentKey);
		final GqElement commitmentB = CommitmentService.getCommitment(witness.get_b(), witness.get_s(), commitmentKey);
		return new HadamardStatement(commitmentsA, commitmentB);
	}
}
