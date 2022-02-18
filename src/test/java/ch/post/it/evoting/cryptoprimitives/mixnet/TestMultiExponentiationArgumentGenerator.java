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

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;

public class TestMultiExponentiationArgumentGenerator {
	private final GqGroupGenerator gqGroupGenerator;
	private final ElGamalGenerator elGamalGenerator;
	private final ZqGroupGenerator zqGroupGenerator;

	public TestMultiExponentiationArgumentGenerator(final GqGroup gqGroup) {
		this.gqGroupGenerator = new GqGroupGenerator(gqGroup);
		this.elGamalGenerator = new ElGamalGenerator(gqGroup);
		this.zqGroupGenerator = new ZqGroupGenerator(ZqGroup.sameOrderAs(gqGroup));
	}

	MultiExponentiationArgument genRandomArgument(final int n, final int m, final int l) {
		final GqElement cA0 = gqGroupGenerator.genMember();
		final GroupVector<GqElement, GqGroup> cB = gqGroupGenerator.genRandomGqElementVector(2 * m);
		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> E = elGamalGenerator.genRandomCiphertextVector(2 * m, l);
		final GroupVector<ZqElement, ZqGroup> a = zqGroupGenerator.genRandomZqElementVector(n);
		final ZqElement r = zqGroupGenerator.genRandomZqElementMember();
		final ZqElement b = zqGroupGenerator.genRandomZqElementMember();
		final ZqElement s = zqGroupGenerator.genRandomZqElementMember();
		final ZqElement tau = zqGroupGenerator.genRandomZqElementMember();
		return new MultiExponentiationArgument.Builder()
				.with_c_A_0(cA0)
				.with_c_B(cB)
				.with_E(E)
				.with_a(a)
				.with_r(r)
				.with_b(b)
				.with_s(s)
				.with_tau(tau)
				.build();
	}
}
