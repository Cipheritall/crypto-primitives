/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GqGroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;

@DisplayName("A ZeroStatement")
class ZeroStatementTest {

	private static final SecureRandom secureRandom = new SecureRandom();
	private static final RandomService randomService = new RandomService();

	private static GqGroup gqGroup;
	private static ZqGroup zqGroup;
	private static GqGroupGenerator gqGroupGenerator;

	private int m;
	private List<GqElement> commitmentsA;
	private List<GqElement> commitmentsB;
	private ZqElement y;

	@BeforeAll
	static void setUpAll() {
		// GqGroup and corresponding ZqGroup set up.
		gqGroup = GqGroupTestData.getGroup();
		zqGroup = ZqGroup.sameOrderAs(gqGroup);
		gqGroupGenerator = new GqGroupGenerator(gqGroup);
	}

	@BeforeEach
	void setUp() {
		m = secureRandom.nextInt(10) + 1;
		commitmentsA = gqGroupGenerator.generateRandomGqElementList(m);
		commitmentsB = gqGroupGenerator.generateRandomGqElementList(m);
		y = ZqElement.create(randomService.genRandomInteger(zqGroup.getQ()), zqGroup);
	}

	@Test
	@DisplayName("constructed with valid parameters works as expected")
	void construct() {
		final ZeroStatement zeroStatement = new ZeroStatement(commitmentsA, commitmentsB, y);

		final GqGroup commitmentsAGroup = zeroStatement.getCommitmentsA().get(0).getGroup();
		final GqGroup commitmentsBGroup = zeroStatement.getCommitmentsB().get(0).getGroup();

		assertEquals(gqGroup, commitmentsAGroup);
		assertEquals(gqGroup, commitmentsBGroup);
		assertEquals(gqGroup.getQ(), zeroStatement.getY().getGroup().getQ());
	}

	@Test
	@DisplayName("constructed with empty commitments works as expected")
	void constructEmptyCommitments() {
		final List<GqElement> emptyCommitmentsA = Collections.emptyList();
		final List<GqElement> emptyCommitmentsB = Collections.emptyList();

		assertDoesNotThrow(() -> new ZeroStatement(emptyCommitmentsA, emptyCommitmentsB, y));
	}

	@Test
	@DisplayName("constructed with any null parameters throws NullPointerException")
	void constructNullParams() {
		final List<GqElement> emptyCommitmentsA = Collections.emptyList();
		final List<GqElement> emptyCommitmentsB = Collections.emptyList();

		assertAll(
				() -> assertThrows(NullPointerException.class, () -> new ZeroStatement(null, commitmentsB, y)),
				() -> assertThrows(NullPointerException.class, () -> new ZeroStatement(commitmentsA, null, y)),
				() -> assertThrows(NullPointerException.class, () -> new ZeroStatement(commitmentsA, commitmentsB, null)),
				() -> assertThrows(NullPointerException.class, () -> new ZeroStatement(null, emptyCommitmentsB, y)),
				() -> assertThrows(NullPointerException.class, () -> new ZeroStatement(emptyCommitmentsA, null, y)),
				() -> assertThrows(NullPointerException.class, () -> new ZeroStatement(emptyCommitmentsA, emptyCommitmentsB, null))
		);
	}

	@Test
	@DisplayName("constructed with commitments of different size throws IllegalArgumentException")
	void constructDiffSizeCommitments() {
		commitmentsB.add(GqElement.create(BigInteger.ONE, gqGroup));

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ZeroStatement(commitmentsA, commitmentsB, y));
		assertEquals("The two commitments vectors must have the same size.", exception.getMessage());
	}

	@Test
	@DisplayName("constructed with commitments from different group throws IllegalArgumentException")
	void constructDiffGroupCommitments() {
		// Generate commitmentsA from different group.
		final GqGroup differentGroup = GqGroupTestData.getDifferentGroup(gqGroup);
		final GqGroupGenerator otherGqGroupGenerator = new GqGroupGenerator(differentGroup);
		final List<GqElement> diffCommitmentsA = otherGqGroupGenerator.generateRandomGqElementList(m);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ZeroStatement(diffCommitmentsA, commitmentsB, y));
		assertEquals("The two commitments must be part of the same group.", exception.getMessage());
	}

	@Test
	@DisplayName("constructed with y from a group of different order throws IllegalArgumentException")
	void constructDiffOrderGroupY() {
		final GqGroup differentGqGroup = GqGroupTestData.getDifferentGroup(gqGroup);
		final ZqGroup differentZqGroup = ZqGroup.sameOrderAs(differentGqGroup);
		final ZqElement differentZqGroupY = ZqElement.create(randomService.genRandomInteger(differentZqGroup.getQ()), differentZqGroup);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ZeroStatement(commitmentsA, commitmentsB, differentZqGroupY));
		assertEquals("The y value group must be of the same order as the group of the commitments.", exception.getMessage());
	}
}