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
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.SecureRandom;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;

class HadamardStatementTest {

	private static final SecureRandom secureRandom = new SecureRandom();

	private GqGroup group;
	private GqGroupGenerator generator;
	private GroupVector<GqElement, GqGroup> commitmentsA;
	private GqElement commitmentB;

	@BeforeEach
	void setup() {
		final int n = secureRandom.nextInt(10) + 1;
		group = GroupTestData.getGqGroup();
		generator = new GqGroupGenerator(group);
		commitmentsA = generator.genRandomGqElementVector(n);
		commitmentB = generator.genMember();
	}

	@Test
	@DisplayName("Constructing a Hadamard statement with valid input does not throw")
	void constructStatement() {
		assertDoesNotThrow(() -> new HadamardStatement(commitmentsA, commitmentB));
	}

	@Test
	@DisplayName("Constructing a Hadamard statement with null arguments should throw a NullPointerException")
	void constructStatementWithNullArguments() {
		assertAll(
				() -> assertThrows(NullPointerException.class, () -> new HadamardStatement(null, commitmentB)),
				() -> assertThrows(NullPointerException.class, () -> new HadamardStatement(commitmentsA, null))
		);
	}

	@Test
	@DisplayName("Constructing a Hadamard statement with commitments A and commitment b of different groups should throw")
	void constructStatementWithCommitmentsFromDifferentGroups() {
		final GqGroup differentGroup = GroupTestData.getDifferentGqGroup(group);
		commitmentB = new GqGroupGenerator(differentGroup).genMember();
		final Exception exception = assertThrows(IllegalArgumentException.class, () -> new HadamardStatement(commitmentsA, commitmentB));
		assertEquals("The commitments A and commitment b must have the same group.", exception.getMessage());
	}
}
