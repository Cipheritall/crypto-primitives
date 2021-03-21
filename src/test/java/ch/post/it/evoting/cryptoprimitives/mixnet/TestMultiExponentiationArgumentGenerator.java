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

import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;

public class TestMultiExponentiationArgumentGenerator {
	private final GqGroupGenerator gqGroupGenerator;
	private final ElGamalGenerator elGamalGenerator;
	private final ZqGroupGenerator zqGroupGenerator;

	public TestMultiExponentiationArgumentGenerator(GqGroup gqGroup) {
		this.gqGroupGenerator = new GqGroupGenerator(gqGroup);
		this.elGamalGenerator = new ElGamalGenerator(gqGroup);
		this.zqGroupGenerator = new ZqGroupGenerator(ZqGroup.sameOrderAs(gqGroup));
	}

	MultiExponentiationArgument genRandomArgument(int n, int m, int l) {
		GqElement cA0 = gqGroupGenerator.genMember();
		GroupVector<GqElement, GqGroup> cB = gqGroupGenerator.genRandomGqElementVector(2 * m);
		GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> E = elGamalGenerator.genRandomCiphertextVector(2 * m, l);
		GroupVector<ZqElement, ZqGroup> a = zqGroupGenerator.genRandomZqElementVector(n);
		ZqElement r = zqGroupGenerator.genRandomZqElementMember();
		ZqElement b = zqGroupGenerator.genRandomZqElementMember();
		ZqElement s = zqGroupGenerator.genRandomZqElementMember();
		ZqElement tau = zqGroupGenerator.genRandomZqElementMember();
		return new MultiExponentiationArgument.Builder()
				.withcA0(cA0)
				.withcBVector(cB)
				.withEVector(E)
				.withaVector(a)
				.withr(r)
				.withb(b)
				.withs(s)
				.withtau(tau)
				.build();
	}
}
