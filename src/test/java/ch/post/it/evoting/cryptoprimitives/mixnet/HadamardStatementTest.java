/*
 * HEADER_LICENSE_OPEN_SOURCE
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

import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GqGroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;

class HadamardStatementTest {

	private static final SecureRandom secureRandom = new SecureRandom();

	private GqGroup group;
	private GqGroupGenerator generator;
	private SameGroupVector<GqElement, GqGroup> commitmentsA;
	private GqElement commitmentB;

	@BeforeEach
	void setup() {
		int n = secureRandom.nextInt(10) + 1;
		group = GqGroupTestData.getGroup();
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
		GqGroup differentGroup = GqGroupTestData.getDifferentGroup(group);
		commitmentB = new GqGroupGenerator(differentGroup).genMember();
		Exception exception = assertThrows(IllegalArgumentException.class, () -> new HadamardStatement(commitmentsA, commitmentB));
		assertEquals("The commitments A and commitment b must have the same group.", exception.getMessage());
	}
}