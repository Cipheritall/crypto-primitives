/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;
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

		CommitmentKeyGenerator ckGenerator = new CommitmentKeyGenerator(gqGroup);
		CommitmentKey commitmentKey = ckGenerator.genCommitmentKey(NUM_ELEMENTS);

		SameGroupVector<ZqElement, ZqGroup> elements = zqGroupGenerator.genRandomZqElementVector(NUM_ELEMENTS);
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
