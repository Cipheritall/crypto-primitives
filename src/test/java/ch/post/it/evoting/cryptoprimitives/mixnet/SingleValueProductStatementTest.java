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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;

@DisplayName("Instantiating a SingleValueProductStatement should...")
class SingleValueProductStatementTest {

	private static final RandomService randomService = new RandomService();
	private static final int NUM_ELEMENTS = 5;

	private GqElement commitment;
	private ZqElement product;

	@BeforeEach
	void setup() {
		GqGroup gqGroup = GroupTestData.getGqGroup();
		ZqGroup zqGroup = ZqGroup.sameOrderAs(gqGroup);
		ZqGroupGenerator zqGroupGenerator = new ZqGroupGenerator(zqGroup);

		TestCommitmentKeyGenerator ckGenerator = new TestCommitmentKeyGenerator(gqGroup);
		CommitmentKey commitmentKey = ckGenerator.genCommitmentKey(NUM_ELEMENTS);

		GroupVector<ZqElement, ZqGroup> elements = zqGroupGenerator.genRandomZqElementVector(NUM_ELEMENTS);
		ZqElement randomness = ZqElement.create(randomService.genRandomInteger(zqGroup.getQ()), zqGroup);
		product = elements.stream().reduce(ZqElement.create(BigInteger.ONE, zqGroup), ZqElement::multiply);
		commitment = CommitmentService.getCommitment(elements, randomness, commitmentKey);
	}

	@Test
	@DisplayName("throw a NullPointerException when passed null arguments")
	void constructSingleValueProductStatementWithNullThrows() {
		assertThrows(NullPointerException.class, () -> new SingleValueProductStatement(null, product));
		assertThrows(NullPointerException.class, () -> new SingleValueProductStatement(commitment, null));
	}

	@Test
	@DisplayName("throw an IllegalArgumentException when the commitment and the product have different orders")
	void constructSingleValueProductStatementWithCommitmentAndProductDifferentQThrows() {
		GqGroup differentGqGroup = GroupTestData.getDifferentGqGroup(commitment.getGroup());
		GqGroupGenerator generator = new GqGroupGenerator(differentGqGroup);
		GqElement differentCommitment = generator.genMember();
		assertThrows(IllegalArgumentException.class, () -> new SingleValueProductStatement(differentCommitment, product));
	}

	@Test
	void testEquals() {
		SingleValueProductStatement singleValueProdStatement1 = new SingleValueProductStatement(commitment, product);
		SingleValueProductStatement singleValueProdStatement2 = new SingleValueProductStatement(commitment, product);
		ZqElement otherProduct = product.add(ZqElement.create(BigInteger.ONE, product.getGroup()));
		SingleValueProductStatement singleValueProdStatement3 = new SingleValueProductStatement(commitment, otherProduct);

		assertEquals(singleValueProdStatement1, singleValueProdStatement1);
		assertEquals(singleValueProdStatement1, singleValueProdStatement2);
		assertNotEquals(singleValueProdStatement1, singleValueProdStatement3);
		assertNotEquals(null, singleValueProdStatement3);
	}
}
