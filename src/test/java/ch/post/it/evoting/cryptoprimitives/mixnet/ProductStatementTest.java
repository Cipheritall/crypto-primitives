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

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;

class ProductStatementTest {

	private static final SecureRandom secureRandom = new SecureRandom();

	private int numElements;
	private GroupVector<GqElement, GqGroup> commitments;
	private ZqElement product;

	@BeforeEach
	void setup() {
		numElements = secureRandom.nextInt(10) + 1;
		final GqGroup gqGroup = GroupTestData.getGqGroup();
		final ZqGroup zqGroup = ZqGroup.sameOrderAs(gqGroup);
		final GqGroupGenerator gqGroupGenerator = new GqGroupGenerator(gqGroup);
		final ZqGroupGenerator zqGroupGenerator = new ZqGroupGenerator(zqGroup);
		commitments = gqGroupGenerator.genRandomGqElementVector(numElements);
		product = zqGroupGenerator.genRandomZqElementMember();
	}

	@Test
	@DisplayName("Instantiating a ProductStatement with null arguments throws a NullPointerException")
	void constructProductStatementWithNull() {
		assertThrows(NullPointerException.class, () -> new ProductStatement(null, product));
		assertThrows(NullPointerException.class, () -> new ProductStatement(commitments, null));
	}

	@Test
	@DisplayName("Instantiating a ProductStatement with commitments and product having a different order q throws an IllegalArgumentException")
	void constructProductStatementWithCommitmentsAndProductDifferentOrders() {
		final GqGroup differentGqGroup = GroupTestData.getDifferentGqGroup(commitments.getGroup());
		commitments = new GqGroupGenerator(differentGqGroup).genRandomGqElementVector(numElements);
		final Exception exception = assertThrows(IllegalArgumentException.class, () -> new ProductStatement(commitments, product));
		assertEquals("The commitments and the product must have the same order q.", exception.getMessage());
	}

	@Test
	@DisplayName("The equals method returns true if and only if the commitments and product are the same")
	void testEquals() {
		final ProductStatement statement1 = new ProductStatement(commitments, product);
		final ProductStatement statement2 = new ProductStatement(commitments, product);

		final List<GqElement> commitmentValues = new ArrayList<>(commitments);
		commitmentValues.add(commitments.getGroup().getIdentity());
		final GroupVector<GqElement, GqGroup> differentCommitments = GroupVector.from(commitmentValues);
		final ProductStatement statement3 = new ProductStatement(differentCommitments, product);

		final ZqElement differentProduct = product.add(ZqElement.create(BigInteger.ONE, product.getGroup()));
		final ProductStatement statement4 = new ProductStatement(commitments, differentProduct);

		assertAll(
				() -> assertEquals(statement1, statement2),
				() -> assertNotEquals(statement1, statement3),
				() -> assertNotEquals(statement1, statement4),
				() -> assertNotEquals(statement3, statement4)
		);
	}
}
