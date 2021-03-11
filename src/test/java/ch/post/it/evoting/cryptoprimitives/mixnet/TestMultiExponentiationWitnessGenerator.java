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

import ch.post.it.evoting.cryptoprimitives.GroupMatrix;
import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;

class TestMultiExponentiationWitnessGenerator {
	private final ZqGroupGenerator zqGroupGenerator;

	TestMultiExponentiationWitnessGenerator(ZqGroup group) {
		this.zqGroupGenerator = new ZqGroupGenerator(group);
	}

	MultiExponentiationWitness genRandomWitness(int n, int m) {
		GroupMatrix<ZqElement, ZqGroup> matrixA = zqGroupGenerator.genRandomZqElementMatrix(n, m);
		GroupVector<ZqElement, ZqGroup> exponentsR = zqGroupGenerator.genRandomZqElementVector(m);
		ZqElement exponentsRho = zqGroupGenerator.genRandomZqElementMember();
		return new MultiExponentiationWitness(matrixA, exponentsR, exponentsRho);
	}
}