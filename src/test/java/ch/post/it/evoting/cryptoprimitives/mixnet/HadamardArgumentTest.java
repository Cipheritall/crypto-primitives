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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;

@DisplayName("constructing a HadamardArgument with...")
class HadamardArgumentTest extends TestGroupSetup {

	private static final int UPPER_BOUND = 10;

	private int m;
	private SameGroupVector<GqElement, GqGroup> commitmentsB;
	private ZeroArgument zeroArgument;

	@BeforeEach
	void setup() {
		final int n = secureRandom.nextInt(UPPER_BOUND) + 1;
		m = secureRandom.nextInt(UPPER_BOUND) + 1;
		final ArgumentGenerator argumentGenerator = new ArgumentGenerator(gqGroup);

		commitmentsB = gqGroupGenerator.genRandomGqElementVector(m);

		zeroArgument = argumentGenerator.genZeroArgument(m, n);
	}

	@Test
	@DisplayName("null arguments throws a NullPointerException")
	void constructHadamardArgumentWithNullArguments() {
		assertThrows(NullPointerException.class, () -> new HadamardArgument(null, zeroArgument));
		assertThrows(NullPointerException.class, () -> new HadamardArgument(commitmentsB, null));
	}

	@Test
	@DisplayName("commitments B and ZeroArgument having a different m throws an IllegalArgumentException")
	void constructHadamardArgumentWithCommitmentsBAndZeroArgumentDifferentSizeM() {
		SameGroupVector<GqElement, GqGroup> differentSizeCommitmentsB = gqGroupGenerator.genRandomGqElementVector(m + 1);
		Exception exception = assertThrows(IllegalArgumentException.class, () -> new HadamardArgument(differentSizeCommitmentsB, zeroArgument));
		assertEquals("The commitments B must be of the same size as the m of the zero argument.", exception.getMessage());
	}

	@Test
	@DisplayName("commitments B and ZeroArgument having different group orders throws an IllegalArgumentException")
	void constructHadamardArgumentWithCommitmentsBAndZeroArgumentDifferentGroupOrder() {
		SameGroupVector<GqElement, GqGroup> otherCommitmentsB = otherGqGroupGenerator.genRandomGqElementVector(m);
		Exception exception = assertThrows(IllegalArgumentException.class, () -> new HadamardArgument(otherCommitmentsB, zeroArgument));
		assertEquals("The commitments B must have the same group order as the zero argument.", exception.getMessage());
	}
}
