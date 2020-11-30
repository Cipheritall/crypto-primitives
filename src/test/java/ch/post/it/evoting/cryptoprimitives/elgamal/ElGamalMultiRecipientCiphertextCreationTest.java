/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.elgamal;

import static ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext.getCiphertext;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GqGroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.utils.GqGroupMemberGenerator;

class ElGamalMultiRecipientCiphertextCreationTest {

	static private final int NUM_RECIPIENTS = 10;

	static private GqGroup gqGroup;
	static private GqElement gqIdentity;
	static private RandomService randomService;
	static private ZqGroup zqGroup;
	static private GqGroupMemberGenerator gqGroupGenerator;
	private static ElGamalMultiRecipientMessage onesMessage;

	private ElGamalMultiRecipientMessage validMessage;
	private ZqElement validExponent;
	private ElGamalMultiRecipientPublicKey validPK;

	@BeforeAll
	static void setUp() {
		gqGroup = GqGroupTestData.getGroup();
		gqIdentity = gqGroup.getIdentity();
		gqGroupGenerator = new GqGroupMemberGenerator(gqGroup);
		zqGroup = ZqGroup.sameOrderAs(gqGroup);
		randomService = new RandomService();
		List<GqElement> ones = Stream.generate(() -> gqGroup.getIdentity()).limit(NUM_RECIPIENTS).collect(Collectors.toList());
		onesMessage = new ElGamalMultiRecipientMessage(ones);
	}

	@BeforeEach
	void setUpEach() {
		List<GqElement> messageElements =
				Stream.generate(() -> gqGroupGenerator.genGqElementMember()).limit(NUM_RECIPIENTS).collect(Collectors.toList());
		validMessage = new ElGamalMultiRecipientMessage(messageElements);

		// genRandomExponent excludes 0 and 1, for getCiphertext, all values in Z_p are allowed
		validExponent = ZqElement.create(randomService.genRandomInteger(zqGroup.getQ()), zqGroup);

		validPK = ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, NUM_RECIPIENTS, randomService).getPublicKey();
	}

	@Nested
	class GenCipherTextTest {
		@Test
		void testNullMessageThrows() {
			assertThrows(NullPointerException.class, () -> getCiphertext(null, validExponent, validPK));
		}

		@Test
		void testNullExponentThrows() {
			assertThrows(NullPointerException.class, () -> getCiphertext(validMessage, null, validPK));
		}

		@Test
		void testNullPublicKeyThrows() {
			assertThrows(NullPointerException.class, () -> getCiphertext(validMessage, validExponent, null));
		}

		@Test
		void testExponentFromDifferentQThrows() {
			GqGroup otherGroup = GqGroupTestData.getDifferentGroup(gqGroup);
			ZqElement otherGroupExponent = randomService.genRandomExponent(ZqGroup.sameOrderAs(otherGroup));

			assertThrows(IllegalArgumentException.class, () -> getCiphertext(validMessage, otherGroupExponent, validPK));
		}

		@Test
		void testMessageAndPublicKeyFromDifferentGroupsThrows() {
			GqGroup otherGroup = GqGroupTestData.getDifferentGroup(gqGroup);
			ElGamalMultiRecipientPublicKey otherGroupPublicKey =
					ElGamalMultiRecipientKeyPair.genKeyPair(otherGroup, 1, randomService).getPublicKey();

			assertThrows(IllegalArgumentException.class, () -> getCiphertext(validMessage, validExponent, otherGroupPublicKey));
		}

		@Test
		void testPublicKeyAndExponentFromDifferentGroupsThrows() {
			GqGroup otherGroup = GqGroupTestData.getDifferentGroup(gqGroup);
			ZqElement otherGroupExponent = randomService.genRandomExponent(ZqGroup.sameOrderAs(otherGroup));

			assertThrows(IllegalArgumentException.class, () -> getCiphertext(validMessage, otherGroupExponent, validPK));
		}

		@Test
		void testMoreMessageElementsThenPublicKeyElementsThrows() {
			ElGamalMultiRecipientPublicKey tooShortPK =
					ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, NUM_RECIPIENTS - 1, randomService).getPublicKey();

			assertThrows(IllegalArgumentException.class, () -> getCiphertext(validMessage, validExponent, tooShortPK));
		}

		@Test
		void testIdentityRandomnessWithNoCompressionAndIdentityMessageElementsThenGammaIsGeneratorAndCiphertextIsPrivateKey() {
			ZqElement one = ZqElement.create(BigInteger.ONE, zqGroup);
			ElGamalMultiRecipientCiphertext ciphertext = getCiphertext(onesMessage, one, validPK);

			assertEquals(gqGroup.getGenerator(), ciphertext.getGamma());
			assertEquals(validPK.toList(), ciphertext.getPhis());
		}

		@Test
		void testFewerMessagesThanKeysWithIdentityRandomnessAndIdentityMessageElementsThenCompression() {
			int nMessages = NUM_RECIPIENTS / 2;
			List<GqElement> oneElements =
					Stream.generate(() -> GqElement.create(BigInteger.ONE, gqGroup)).limit(nMessages).collect(Collectors.toList());
			ElGamalMultiRecipientMessage smallOneMessage = new ElGamalMultiRecipientMessage(oneElements);
			ZqElement oneExponent = ZqElement.create(BigInteger.ONE, zqGroup);
			ElGamalMultiRecipientCiphertext ciphertext = getCiphertext(smallOneMessage, oneExponent, validPK);

			//With a exponent of one and message of ones, the ciphertext is just the public key
			assertEquals(validPK.toList().subList(0, nMessages - 1), ciphertext.getPhis().subList(0, nMessages - 1));

			GqElement compressedKey =
					validPK
							.toList()
							.subList(nMessages - 1, NUM_RECIPIENTS)
							.stream()
							.reduce(GqElement::multiply)
							.orElseThrow(() -> new RuntimeException("Should not reach"));
			assertEquals(compressedKey, ciphertext.getPhis().get(nMessages - 1));
		}

		@Test
		void testZeroExponentGivesMessage() {
			ZqElement zeroExponent = ZqElement.create(BigInteger.ZERO, zqGroup);
			ElGamalMultiRecipientCiphertext ciphertext = getCiphertext(validMessage, zeroExponent, validPK);
			assertEquals(validMessage.toList(), ciphertext.getPhis());
			assertEquals(gqIdentity, ciphertext.getGamma());
		}

		@Test
		void testSpecificValues() {
			GqGroup group = new GqGroup(BigInteger.valueOf(11), BigInteger.valueOf(5), BigInteger.valueOf(3));
			ElGamalMultiRecipientMessage message =
					new ElGamalMultiRecipientMessage(
							Arrays.asList(
									GqElement.create(BigInteger.valueOf(4), group),
									GqElement.create(BigInteger.valueOf(5), group)
							)
					);
			ZqElement exponent = ZqElement.create(BigInteger.valueOf(2), ZqGroup.sameOrderAs(group));
			ElGamalMultiRecipientPublicKey publicKey =
					new ElGamalMultiRecipientPublicKey(
							Arrays.asList(
									GqElement.create(BigInteger.valueOf(5), group),
									GqElement.create(BigInteger.valueOf(9), group)
							)
					);
			ElGamalMultiRecipientCiphertext ciphertext =
					ElGamalMultiRecipientCiphertext.create(
							GqElement.create(BigInteger.valueOf(9), group),
							Arrays.asList(
									GqElement.create(BigInteger.valueOf(1), group),
									GqElement.create(BigInteger.valueOf(9), group)
							)
					);

			assertEquals(ciphertext, getCiphertext(message, exponent, publicKey));
		}
	}
}
