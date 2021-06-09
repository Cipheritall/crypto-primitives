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
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;

/**
 * Allow to generate at random, based on a gqGroup, the different argument needed in various tests.
 */
class TestArgumentGenerator {

	private final GqGroupGenerator gqGroupGenerator;
	private final ZqGroupGenerator zqGroupGenerator;
	private final ElGamalGenerator elGamalGenerator;

	TestArgumentGenerator(final GqGroup gqGroup) {
		this.gqGroupGenerator = new GqGroupGenerator(gqGroup);
		this.zqGroupGenerator = new ZqGroupGenerator(ZqGroup.sameOrderAs(gqGroup));
		this.elGamalGenerator = new ElGamalGenerator(gqGroup);
	}

	ZeroArgument genZeroArgument(final int m, final int n) {
		return new ZeroArgument.Builder()
				.with_c_A_0(gqGroupGenerator.genMember())
				.with_c_B_m(gqGroupGenerator.genMember())
				.with_c_d(gqGroupGenerator.genRandomGqElementVector(2 * m + 1))
				.with_a_prime(zqGroupGenerator.genRandomZqElementVector(n))
				.with_b_prime(zqGroupGenerator.genRandomZqElementVector(n))
				.with_r_prime(zqGroupGenerator.genRandomZqElementMember())
				.with_s_prime(zqGroupGenerator.genRandomZqElementMember())
				.with_t_prime(zqGroupGenerator.genRandomZqElementMember())
				.build();
	}

	SingleValueProductArgument genSingleValueProductArgument(final int n) {
		return new SingleValueProductArgument.Builder()
				.with_c_d(gqGroupGenerator.genMember())
				.with_c_delta(gqGroupGenerator.genMember())
				.with_c_Delta(gqGroupGenerator.genMember())
				.with_a_tilde(zqGroupGenerator.genRandomZqElementVector(n))
				.with_b_tilde(zqGroupGenerator.genRandomZqElementVector(n))
				.with_r_tilde(zqGroupGenerator.genRandomZqElementMember())
				.with_s_tilde(zqGroupGenerator.genRandomZqElementMember())
				.build();
	}

	HadamardArgument genHadamardArgument(final int m, final int n) {
		final GroupVector<GqElement, GqGroup> commitmentsB = gqGroupGenerator.genRandomGqElementVector(m);
		final ZeroArgument zeroArgument = genZeroArgument(m, n);

		return new HadamardArgument(commitmentsB, zeroArgument);
	}

	ProductArgument genProductArgument(final int m, final int n) {
		final SingleValueProductArgument singleValueProductArgument = genSingleValueProductArgument(n);

		if (m == 1) {
			return new ProductArgument(singleValueProductArgument);
		} else {
			final GqElement commitmentB = gqGroupGenerator.genMember();
			final HadamardArgument hadamardArgument = genHadamardArgument(m, n);

			return new ProductArgument(commitmentB, hadamardArgument, singleValueProductArgument);
		}
	}

	MultiExponentiationArgument genMultiExponentiationArgument(final int m, final int n, final int l) {
		return new MultiExponentiationArgument.Builder()
				.with_c_A_0(gqGroupGenerator.genMember())
				.with_c_B(gqGroupGenerator.genRandomGqElementVector(2 * m))
				.with_E(elGamalGenerator.genRandomCiphertextVector(2 * m, l))
				.with_a(zqGroupGenerator.genRandomZqElementVector(n))
				.with_r(zqGroupGenerator.genRandomZqElementMember())
				.with_b(zqGroupGenerator.genRandomZqElementMember())
				.with_s(zqGroupGenerator.genRandomZqElementMember())
				.with_tau(zqGroupGenerator.genRandomZqElementMember())
				.build();
	}

	ShuffleArgument genShuffleArgument(final int m, final int n, final int l) {
		return new ShuffleArgument.Builder()
				.with_c_A(gqGroupGenerator.genRandomGqElementVector(m))
				.with_c_B(gqGroupGenerator.genRandomGqElementVector(m))
				.with_productArgument(this.genProductArgument(m, n))
				.with_multiExponentiationArgument(this.genMultiExponentiationArgument(m, n, l))
				.build();
	}

}
