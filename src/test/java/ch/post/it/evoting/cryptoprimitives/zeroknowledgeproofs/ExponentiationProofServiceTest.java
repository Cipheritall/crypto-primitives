package ch.post.it.evoting.cryptoprimitives.zeroknowledgeproofs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GroupTestData;

class ExponentiationProofServiceTest extends TestGroupSetup {

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