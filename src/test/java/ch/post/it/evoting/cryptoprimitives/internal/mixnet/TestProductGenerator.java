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
package ch.post.it.evoting.cryptoprimitives.internal.mixnet;

import java.math.BigInteger;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupMatrix;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.mixnet.ProductStatement;
import ch.post.it.evoting.cryptoprimitives.mixnet.ProductWitness;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;

class TestProductGenerator {

	static ProductWitness genProductWitness(final int n, final int m, final ZqGroupGenerator zqGroupGenerator) {
		final GroupMatrix<ZqElement, ZqGroup> matrixA = zqGroupGenerator.genRandomZqElementMatrix(n, m);
		final GroupVector<ZqElement, ZqGroup> exponentsR = zqGroupGenerator.genRandomZqElementVector(m);
		return new ProductWitness(matrixA, exponentsR);
	}

	static ProductStatement getProductStatement(final ProductWitness witness, final CommitmentKey commitmentKey) {
		final GroupMatrix<ZqElement, ZqGroup> matrixA = witness.get_A();
		final GroupVector<ZqElement, ZqGroup> exponentsR = witness.get_r();
		final GroupVector<GqElement, GqGroup> commitmentsA = CommitmentService.getCommitmentMatrix(matrixA, exponentsR, commitmentKey);
		final ZqElement one = ZqElement.create(BigInteger.ONE, matrixA.getGroup());
		final ZqElement productB = matrixA.flatStream().reduce(one, ZqElement::multiply);
		return new ProductStatement(commitmentsA, productB);
	}
}
