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

import java.math.BigInteger;

import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;

public class SingleValueProductGenerator {

	static SingleValueProductWitness genSingleValueProductWitness(final ZqGroupGenerator zqGroupGenerator, final int numElements) {
		final GroupVector<ZqElement, ZqGroup> elements = zqGroupGenerator.genRandomZqElementVector(numElements);
		final ZqElement randomness = zqGroupGenerator.genRandomZqElementMember();

		return new SingleValueProductWitness(elements, randomness);
	}

	static SingleValueProductStatement genSingleValueProductStatement(final ZqGroupGenerator zqGroupGenerator, final GqGroupGenerator gqGroupGenerator) {
		final ZqElement product = zqGroupGenerator.genRandomZqElementMember();
		final GqElement commitment = gqGroupGenerator.genMember();

		return new SingleValueProductStatement(commitment, product);
	}

	static SingleValueProductStatement getSingleValueProductStatement(final SingleValueProductWitness witness, final CommitmentKey commitmentKey) {
		final GroupVector<ZqElement, ZqGroup> elements = witness.getElements();
		final ZqElement randomness = witness.getRandomness();
		final ZqGroup zqGroup = elements.getGroup();
		final ZqElement product = elements.stream().reduce(ZqElement.create(BigInteger.ONE, zqGroup), ZqElement::multiply);
		final GqElement commitment = CommitmentService.getCommitment(elements, randomness, commitmentKey);

		return new SingleValueProductStatement(commitment, product);
	}
}
