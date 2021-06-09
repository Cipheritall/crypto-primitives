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
package ch.post.it.evoting.cryptoprimitives.zeroknowledgeproofs;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.hashing.TestHashService;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GroupTestData;

class ExponentiationProofServiceTest extends TestGroupSetup {

	private static final int MAX_NUMBER_EXPONENTIATIONS = 10;
	private static RandomService randomService;
	private static HashService hashService;
	private static ExponentiationProofService proofService;

	@BeforeAll
	static void setupAll() {
		randomService = new RandomService();
		hashService = TestHashService.create(gqGroup.getQ());
		proofService = new ExponentiationProofService(randomService, hashService);
	}

	@Test
	void constructorNotNullChecks() {
		assertThrows(NullPointerException.class, () -> new ExponentiationProofService(null, hashService));
		assertThrows(NullPointerException.class, () -> new ExponentiationProofService(randomService, null));
	}

	@Nested
	class ComputePhiExponentiationTest {
		private ZqElement preimage;
		private GroupVector<GqElement, GqGroup> bases;

		@BeforeEach
		void setup() {
			final int n = secureRandom.nextInt(10) + 1;
			preimage = zqGroupGenerator.genRandomZqElementMember();
			bases = gqGroupGenerator.genRandomGqElementVector(n);
		}

		@Test
		void notNullChecks() {
			assertThrows(NullPointerException.class, () -> ExponentiationProofService.computePhiExponentiation(null, bases));
			assertThrows(NullPointerException.class, () -> ExponentiationProofService.computePhiExponentiation(preimage, null));
		}

		@Test
		void basesNotEmptyCheck() {
			final GroupVector<GqElement, GqGroup> emptyBases = GroupVector.of();
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> ExponentiationProofService.computePhiExponentiation(preimage, emptyBases));
			assertEquals("The vector of bases must contain at least 1 element.", exception.getMessage());
		}

		@Test
		void sameGroupOrderCheck() {
			final ZqElement otherpreimage = otherZqGroupGenerator.genRandomZqElementMember();
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> ExponentiationProofService.computePhiExponentiation(otherpreimage, bases));
			assertEquals("The preimage and the bases must have the same group order.", exception.getMessage());
		}

		@RepeatedTest(10)
		void phiFunctionSize() {
			assertEquals(bases.size(), ExponentiationProofService.computePhiExponentiation(preimage, bases).size());
		}

		@Test
		void withSpecificValues() {
			final GqGroup gqGroup = GroupTestData.getGroupP59();
			final ZqElement preimage = ZqElement.create(3, ZqGroup.sameOrderAs(gqGroup));
			final GroupVector<GqElement, GqGroup> bases = GroupVector.of(GqElement.create(BigInteger.ONE, gqGroup),
					GqElement.create(BigInteger.valueOf(4), gqGroup),
					GqElement.create(BigInteger.valueOf(9), gqGroup));

			final GroupVector<GqElement, GqGroup> expected = GroupVector.of(GqElement.create(BigInteger.ONE, gqGroup),
					GqElement.create(BigInteger.valueOf(5), gqGroup),
					GqElement.create(BigInteger.valueOf(21), gqGroup));
			assertEquals(expected, ExponentiationProofService.computePhiExponentiation(preimage, bases));
		}
	}

	@Nested
	class GenExponentiationProofTest {

		private final List<String> auxiliaryInformation = Arrays.asList("aux", "1");
		private int n;
		private GroupVector<GqElement, GqGroup> bases;
		private ZqElement exponent;
		private GroupVector<GqElement, GqGroup> exponentiations;

		@BeforeEach
		void setup() {
			n = secureRandom.nextInt(MAX_NUMBER_EXPONENTIATIONS) + 1;
			bases = gqGroupGenerator.genRandomGqElementVector(n);
			exponent = zqGroupGenerator.genRandomZqElementMember();
			exponentiations = ExponentiationProofService.computePhiExponentiation(exponent, bases);
		}

		@Test
		void notNullChecks() {
			assertThrows(NullPointerException.class,
					() -> proofService.genExponentiationProof(null, exponent, exponentiations, auxiliaryInformation));
			assertThrows(NullPointerException.class, () -> proofService.genExponentiationProof(bases, null, exponentiations, auxiliaryInformation));
			assertThrows(NullPointerException.class, () -> proofService.genExponentiationProof(bases, exponent, null, auxiliaryInformation));
			assertThrows(NullPointerException.class, () -> proofService.genExponentiationProof(bases, exponent, exponentiations, null));
		}

		@Test
		void validArguments() {
			assertDoesNotThrow(() -> proofService.genExponentiationProof(bases, exponent, exponentiations, auxiliaryInformation));
			assertDoesNotThrow(() -> proofService.genExponentiationProof(bases, exponent, exponentiations, Collections.emptyList()));
		}

		@Test
		void auxiliaryInformationDoesNotContainNullCheck() {
			final List<String> auxiliaryInformationWithNull = Arrays.asList("test", null);
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> proofService.genExponentiationProof(bases, exponent, exponentiations, auxiliaryInformationWithNull));
			assertEquals("The auxiliary information must not contain null objects.", exception.getMessage());
		}

		@Test
		void basesNotEmptyCheck() {
			final GroupVector<GqElement, GqGroup> emptyBases = GroupVector.of();
			IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> proofService.genExponentiationProof(emptyBases, exponent, exponentiations, auxiliaryInformation));
			assertEquals("The bases must contain at least 1 element.", exception.getMessage());
		}

		@Test
		void basesAndExponentiationsSameSizeCheck() {
			bases = bases.append(gqGroupGenerator.genMember());
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> proofService.genExponentiationProof(bases, exponent, exponentiations, auxiliaryInformation));
			assertEquals("Bases and exponentiations must have the same size.", exception.getMessage());
		}


		@Test
		void basesAndExponentiationsSameGroupCheck() {
			exponentiations = otherGqGroupGenerator.genRandomGqElementVector(n);
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> proofService.genExponentiationProof(bases, exponent, exponentiations, auxiliaryInformation));
			assertEquals("Bases and exponentiations must have the same group.", exception.getMessage());
		}


		@Test
		void exponentSameGroupOrderThanExponentiationsCheck() {
			exponent = otherZqGroupGenerator.genRandomZqElementMember();
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> proofService.genExponentiationProof(bases, exponent, exponentiations, auxiliaryInformation));
			assertEquals("The exponent and the exponentiations must have the same group order.", exception.getMessage());
		}

		@Test
		void exponentiationsArePhiExponentiationCheck() {
			final ZqElement otherExponent = exponent.add(ZqElement.create(BigInteger.ONE, zqGroup));
			exponentiations = ExponentiationProofService.computePhiExponentiation(otherExponent, bases);
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> proofService.genExponentiationProof(bases, exponent, exponentiations, auxiliaryInformation));
			assertEquals("The exponentiations must correspond to the exponent's and bases' phi exponentiation.", exception.getMessage());
		}

		@Test
		void specificValuesGiveExpectedResult() {
			final BigInteger p = BigInteger.valueOf(11);
			final BigInteger q = BigInteger.valueOf(5);
			final BigInteger g = BigInteger.valueOf(3);
			final GqGroup gqGroup = new GqGroup(p, q, g);
			final ZqGroup zqGroup = new ZqGroup(q);

			final GqElement gThree = GqElement.create(BigInteger.valueOf(3), gqGroup);
			final GqElement gFour = GqElement.create(BigInteger.valueOf(4), gqGroup);
			final GqElement gFive = GqElement.create(BigInteger.valueOf(5), gqGroup);
			final GqElement gNine = GqElement.create(BigInteger.valueOf(9), gqGroup);

			// Input.
			final GroupVector<GqElement, GqGroup> bases = GroupVector.of(gFour, gThree);
			final ZqElement exponent = ZqElement.create(BigInteger.valueOf(3), zqGroup);
			final GroupVector<GqElement, GqGroup> exponentiations = GroupVector.of(gNine, gFive);
			final List<String> auxiliaryInformation = Arrays.asList("specific", "test", "values");

			// Fix random values
			final RandomService randomService = new RandomService() {
				final Iterator<BigInteger> values = Collections.singletonList(BigInteger.valueOf(2)).iterator();

				@Override
				public BigInteger genRandomInteger(BigInteger upperBound) {
					return values.next();
				}
			};
			final HashService hashService = TestHashService.create(q);
			final ExponentiationProofService proofService = new ExponentiationProofService(randomService, hashService);

			// Expected result
			final ZqElement e = ZqElement.create(BigInteger.valueOf(3), zqGroup);
			final ZqElement z = ZqElement.create(BigInteger.ONE, zqGroup);
			final ExponentiationProof expected = new ExponentiationProof(e, z);

			assertEquals(expected, proofService.genExponentiationProof(bases, exponent, exponentiations, auxiliaryInformation));
		}
	}
}