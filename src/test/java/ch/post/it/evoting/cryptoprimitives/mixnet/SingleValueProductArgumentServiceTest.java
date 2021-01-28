/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.HashService;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientKeyPair;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GqGroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;

class SingleValueProductArgumentServiceTest {

	private static final int NUM_ELEMENTS = 5;
	private static final RandomService randomService = new RandomService();

	private static ZqGroup zqGroup;
	private static CommitmentKey commitmentKey;
	private static SingleValueProductArgumentService svpArgumentProvider;

	private GqElement commitment;
	private ZqElement product;
	private List<ZqElement> elements;
	private ZqElement randomness;

	private SingleValueProductStatement statement;
	private SingleValueProductWitness witness;

	@BeforeAll
	static void setupAll() {
		GqGroup gqGroup = GqGroupTestData.getGroup();
		zqGroup = ZqGroup.sameOrderAs(gqGroup);

		ElGamalMultiRecipientKeyPair keyPair = ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, NUM_ELEMENTS, randomService);
		ElGamalMultiRecipientPublicKey publicKey = keyPair.getPublicKey();
		commitmentKey = genCommitmentKey(gqGroup, NUM_ELEMENTS);
		HashService hashService = mock(HashService.class);
		when(hashService.recursiveHash(any()))
				.thenReturn(new byte[] { 0b10 });
		svpArgumentProvider = new SingleValueProductArgumentService(randomService, hashService, publicKey, commitmentKey);
	}

	@BeforeEach
	void setup() {
		elements = Stream.generate(() -> randomService.genRandomExponent(zqGroup)).limit(NUM_ELEMENTS).collect(Collectors.toList());
		randomness = ZqElement.create(randomService.genRandomInteger(zqGroup.getQ()), zqGroup);
		product = elements.stream().reduce(ZqElement.create(BigInteger.ONE, zqGroup), ZqElement::multiply);
		commitment = CommitmentService.getCommitment(elements, randomness, commitmentKey);

		statement = new SingleValueProductStatement(commitment, product);
		witness = new SingleValueProductWitness(elements, randomness);
	}

	@RepeatedTest(10)
	void getSingleValueProductArgumentDoesNotThrow() {
		assertDoesNotThrow(() -> svpArgumentProvider.getSingleValueProductArgument(statement, witness));
	}

	@Test
	@DisplayName("getSingleValueProductArgument with null input throws NullPointerException")
	void getSingleValueProductArgumentWithNullThrows() {
		assertAll(
				() -> assertThrows(NullPointerException.class, () -> svpArgumentProvider.getSingleValueProductArgument(null, witness)),
				() -> assertThrows(NullPointerException.class, () -> svpArgumentProvider.getSingleValueProductArgument(statement, null))
		);
	}

	@Test
	@DisplayName("getSingleValueProductArgument with statement groups different from commitment key group throws IllegalArgumentException")
	void getSingleValueProductArgumentWithStatementFromDifferentGroupsThrows() {
		GqGroup differentGqGroup = GqGroupTestData.getDifferentGroup(commitmentKey.getGroup());
		ZqGroup differentZqGroup = ZqGroup.sameOrderAs(differentGqGroup);
		GqElement differentCommitment = differentGqGroup.getIdentity();
		ZqElement differentProduct = differentZqGroup.getIdentity();
		SingleValueProductStatement differentStatement = new SingleValueProductStatement(differentCommitment, differentProduct);
		Exception exception = assertThrows(IllegalArgumentException.class,
				() -> svpArgumentProvider.getSingleValueProductArgument(differentStatement, witness));
		assertEquals("The statement's groups must have the same order as the commitment key's group.", exception.getMessage());
	}

	@Test
	@DisplayName("getSingleValueProductArgument with witness group order different from commitment key group order throws IllegalArgumentException")
	void getSingleValueProductArgumentWithWitnessFromDifferentGroupThrows() {
		GqGroup differentGqGroup = GqGroupTestData.getDifferentGroup(commitmentKey.getGroup());
		ZqGroup differentZqGroup = ZqGroup.sameOrderAs(differentGqGroup);
		List<ZqElement> differentElements = Stream.generate(() -> randomService.genRandomExponent(differentZqGroup)).limit(NUM_ELEMENTS)
				.collect(Collectors.toList());
		ZqElement differentRandomness = ZqElement.create(randomService.genRandomInteger(differentZqGroup.getQ()), differentZqGroup);
		SingleValueProductWitness differentWitness = new SingleValueProductWitness(differentElements, differentRandomness);
		Exception exception = assertThrows(IllegalArgumentException.class,
				() -> svpArgumentProvider.getSingleValueProductArgument(statement, differentWitness));
		assertEquals("The witness' group must have the same order as the commitment key's group.", exception.getMessage());
	}

	@Test
	@DisplayName("getSingleValueProductArgument with incorrect commitment throws IllegalArgumentException")
	void getSingleValueProductArgumentWithWrongCommitmentThrows() {
		GqElement wrongCommitment = commitment.multiply(commitment.getGroup().getGenerator());
		SingleValueProductStatement wrongStatement = new SingleValueProductStatement(wrongCommitment, product);
		Exception exception = assertThrows(IllegalArgumentException.class,
				() -> svpArgumentProvider.getSingleValueProductArgument(wrongStatement, witness));
		assertEquals("The provided commitment does not correspond to the elements, randomness and commitment key provided.",
				exception.getMessage());
	}

	@Test
	@DisplayName("getSingleValueProductArgument with incorrect product throws IllegalArgumentException")
	void getSingleValueProductArgumentWithWrongProductThrows() {
		ZqElement wrongProduct = product.add(ZqElement.create(BigInteger.ONE, product.getGroup()));
		SingleValueProductStatement wrongStatement = new SingleValueProductStatement(commitment, wrongProduct);
		Exception exception = assertThrows(IllegalArgumentException.class,
				() -> svpArgumentProvider.getSingleValueProductArgument(wrongStatement, witness));
		assertEquals("The product of the provided elements does not give the provided product.", exception.getMessage());
	}

	@Test
	@DisplayName("getSingleValueProductArgument with specific values gives expected result")
	void getSingleValueProductArgumentWithSpecificValues() {
		GqGroup specificGqGroup = new GqGroup(BigInteger.valueOf(23), BigInteger.valueOf(11), BigInteger.valueOf(6));
		ZqGroup specificZqGroup = ZqGroup.sameOrderAs(specificGqGroup);
		// commitment = 3
		GqElement commitment = GqElement.create(BigInteger.valueOf(3), specificGqGroup);
		// product = 9
		ZqElement product = ZqElement.create(BigInteger.valueOf(9), specificZqGroup);
		// a = (2, 10)
		List<ZqElement> a = new ArrayList<>();
		a.add(ZqElement.create(BigInteger.valueOf(2), specificZqGroup));
		a.add(ZqElement.create(BigInteger.valueOf(10), specificZqGroup));
		// r = 5
		ZqElement r = ZqElement.create(BigInteger.valueOf(5), specificZqGroup);
		// pk = (8, 16)
		List<GqElement> pkElements = new ArrayList<>(2);
		pkElements.add(GqElement.create(BigInteger.valueOf(8), specificGqGroup));
		pkElements.add(GqElement.create(BigInteger.valueOf(16), specificGqGroup));
		ElGamalMultiRecipientPublicKey pk = new ElGamalMultiRecipientPublicKey(pkElements);
		// ck = (2, 3, 4)
		List<GqElement> gElements = new ArrayList<>(2);
		GqElement h = GqElement.create(BigInteger.valueOf(2), specificGqGroup);
		gElements.add(GqElement.create(BigInteger.valueOf(3), specificGqGroup));
		gElements.add(GqElement.create(BigInteger.valueOf(4), specificGqGroup));
		CommitmentKey ck = new CommitmentKey(h, gElements);
		// expected = (16, 2, 6, (1, 8), (1, 9), 5, 7)
		GqElement cd = GqElement.create(BigInteger.valueOf(16), specificGqGroup);
		GqElement cdelta = GqElement.create(BigInteger.valueOf(2), specificGqGroup);
		GqElement cDelta = GqElement.create(BigInteger.valueOf(6), specificGqGroup);
		List<ZqElement> aTilde = new ArrayList<>(2);
		aTilde.add(ZqElement.create(BigInteger.valueOf(1), specificZqGroup));
		aTilde.add(ZqElement.create(BigInteger.valueOf(8), specificZqGroup));
		List<ZqElement> bTilde = new ArrayList<>(2);
		bTilde.add(ZqElement.create(BigInteger.valueOf(1), specificZqGroup));
		bTilde.add(ZqElement.create(BigInteger.valueOf(9), specificZqGroup));
		ZqElement rTilde = ZqElement.create(BigInteger.valueOf(5), specificZqGroup);
		ZqElement sTilde = ZqElement.create(BigInteger.valueOf(7), specificZqGroup);
		SingleValueProductArgument expected = new SingleValueProductArgument.SingleValueProductArgumentBuilder()
				.withCLowerD(cd)
				.withCLowerDelta(cdelta)
				.withCUpperDelta(cDelta)
				.withATilde(new SameGroupVector<>(aTilde))
				.withBTilde(new SameGroupVector<>(bTilde))
				.withRTilde(rTilde)
				.withSTilde(sTilde)
				.build();

		//Mock random integers
		RandomService randomService = mock(RandomService.class);
		when(randomService.genRandomInteger(specificZqGroup.getQ()))
				.thenReturn(BigInteger.valueOf(3), BigInteger.valueOf(7), // d_0, d_1
						BigInteger.valueOf(10),                              // r_d
						BigInteger.valueOf(4), BigInteger.valueOf(8));      // s_0, s_x

		SingleValueProductStatement statement = new SingleValueProductStatement(commitment, product);
		SingleValueProductWitness witness = new SingleValueProductWitness(a, r);

		HashService hashService = mock(HashService.class);
		when(hashService.recursiveHash(any()))
				.thenReturn(new byte[] { 0b1010 });
		SingleValueProductArgumentService svpArgumentProvider = new SingleValueProductArgumentService(randomService, hashService, pk, ck);
		assertEquals(expected, svpArgumentProvider.getSingleValueProductArgument(statement, witness));
	}

	protected static CommitmentKey genCommitmentKey(GqGroup group, int k) {
		GqGroupGenerator generator = new GqGroupGenerator(group);
		GqElement h = generator.genNonIdentityNonGeneratorMember();
		List<GqElement> gList = Stream.generate(generator::genNonIdentityNonGeneratorMember).limit(k).collect(Collectors.toList());
		return new CommitmentKey(h, gList);
	}

}