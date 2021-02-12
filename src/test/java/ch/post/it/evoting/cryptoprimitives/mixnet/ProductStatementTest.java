/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;
import java.util.stream.Collectors;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GqGroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;

class ProductStatementTest {

	private static final SecureRandom secureRandom = new SecureRandom();

	private int numElements;
	private SameGroupVector<GqElement, GqGroup> commitments;
	private ZqElement product;

	@BeforeEach
	void setup() {
		numElements = secureRandom.nextInt(10) + 1;
		GqGroup gqGroup = GqGroupTestData.getGroup();
		ZqGroup zqGroup = ZqGroup.sameOrderAs(gqGroup);
		GqGroupGenerator gqGroupGenerator = new GqGroupGenerator(gqGroup);
		ZqGroupGenerator zqGroupGenerator = new ZqGroupGenerator(zqGroup);
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
		GqGroup differentGqGroup = GqGroupTestData.getDifferentGroup(commitments.getGroup());
		commitments = new GqGroupGenerator(differentGqGroup).genRandomGqElementVector(numElements);
		Exception exception = assertThrows(IllegalArgumentException.class, () -> new ProductStatement(commitments, product));
		assertEquals("The commitments and the product must have the same order q.", exception.getMessage());
	}

	@Test
	@DisplayName("The equals method returns true if and only if the commitments and product are the same")
	void testEquals() {
		ProductStatement statement1 = new ProductStatement(commitments, product);
		ProductStatement statement2 = new ProductStatement(commitments, product);

		List<GqElement> commitmentValues = commitments.stream().collect(Collectors.toList());
		commitmentValues.add(commitments.getGroup().getIdentity());
		SameGroupVector<GqElement, GqGroup> differentCommitments = new SameGroupVector<>(commitmentValues);
		ProductStatement statement3 = new ProductStatement(differentCommitments, product);

		ZqElement differentProduct = product.add(ZqElement.create(BigInteger.ONE, product.getGroup()));
		ProductStatement statement4 = new ProductStatement(commitments, differentProduct);

		assertAll(
				() -> assertEquals(statement1, statement2),
				() -> assertNotEquals(statement1, statement3),
				() -> assertNotEquals(statement1, statement4),
				() -> assertNotEquals(statement3, statement4)
		);
	}
}