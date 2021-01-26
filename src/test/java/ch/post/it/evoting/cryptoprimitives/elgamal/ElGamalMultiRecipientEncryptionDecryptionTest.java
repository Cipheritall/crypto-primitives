package ch.post.it.evoting.cryptoprimitives.elgamal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GqGroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;

class ElGamalMultiRecipientEncryptionDecryptionTest {

	private static final int NUM_ELEMENTS = 10;

	private static RandomService randomService;
	private static GqGroup gqGroup;
	private static GqGroupGenerator generator;
	private static ZqGroup zqGroup;

	private static ElGamalMultiRecipientMessage message;

	@BeforeAll
	static void setUpAll() {
		randomService = new RandomService();
		gqGroup = GqGroupTestData.getGroup();
		zqGroup = ZqGroup.sameOrderAs(gqGroup);
		generator = new GqGroupGenerator(gqGroup);
	}

	@BeforeEach
	void setUp() {
		List<GqElement> validMessageElements = Stream.generate(generator::genMember).limit(NUM_ELEMENTS).collect(Collectors.toList());
		message = new ElGamalMultiRecipientMessage(validMessageElements);
	}

	@RepeatedTest(10)
	void testEncryptAndDecryptGivesOriginalMessage() {
		ElGamalMultiRecipientKeyPair keyPair = ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, NUM_ELEMENTS, randomService);
		ZqElement exponent = randomService.genRandomExponent(zqGroup);
		ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertext.getCiphertext(message, exponent, keyPair.getPublicKey());
		ElGamalMultiRecipientMessage decryptedMessage = ElGamalMultiRecipientMessage.getMessage(ciphertext, keyPair.getPrivateKey());

		assertEquals(message, decryptedMessage);
	}

	@RepeatedTest(10)
	void testEncryptAndDecryptWithLongerKeysGivesOriginalMessage() {
		ElGamalMultiRecipientKeyPair keyPair = ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, NUM_ELEMENTS+1, randomService);
		ZqElement exponent = randomService.genRandomExponent(zqGroup);
		ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertext.getCiphertext(message, exponent, keyPair.getPublicKey());
		ElGamalMultiRecipientMessage decryptedMessage = ElGamalMultiRecipientMessage.getMessage(ciphertext, keyPair.getPrivateKey());

		assertEquals(message, decryptedMessage);
	}

	@Test
	void testEncryptAndDecryptWithDifferentKeysGivesDifferentMessage() {
		ElGamalMultiRecipientKeyPair keyPair = ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, NUM_ELEMENTS, randomService);
		ZqElement exponent = randomService.genRandomExponent(zqGroup);
		ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertext.getCiphertext(message, exponent, keyPair.getPublicKey());
		ElGamalMultiRecipientKeyPair differentKeyPair;
		do {
			differentKeyPair = ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, NUM_ELEMENTS, randomService);
		} while (differentKeyPair.equals(keyPair));
		ElGamalMultiRecipientMessage differentMessage = ElGamalMultiRecipientMessage.getMessage(ciphertext, differentKeyPair.getPrivateKey());

		assertNotEquals(message, differentMessage);
	}

	@Test
	void testEncryptAndDecryptWithDifferentLongerKeysGivesDifferentMessage() {
		ElGamalMultiRecipientKeyPair keyPair = ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, NUM_ELEMENTS+1, randomService);
		ZqElement exponent = randomService.genRandomExponent(zqGroup);
		ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertext.getCiphertext(message, exponent, keyPair.getPublicKey());
		ElGamalMultiRecipientKeyPair differentKeyPair;
		do {
			differentKeyPair = ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, NUM_ELEMENTS+1, randomService);
		} while (differentKeyPair.equals(keyPair));
		ElGamalMultiRecipientMessage differentMessage = ElGamalMultiRecipientMessage.getMessage(ciphertext, differentKeyPair.getPrivateKey());

		assertNotEquals(message, differentMessage);
	}

	@Test
	void testEncryptAndDecryptWithDifferentKeySizesGivesDifferentMessage() {
		ElGamalMultiRecipientKeyPair keyPair = ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, NUM_ELEMENTS+1, randomService);
		ZqElement exponent = randomService.genRandomExponent(zqGroup);
		ElGamalMultiRecipientPublicKey publicKey =
				new ElGamalMultiRecipientPublicKey(keyPair.getPublicKey().stream().limit(NUM_ELEMENTS).collect(Collectors.toList()));
		ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertext.getCiphertext(message, exponent, publicKey);
		ElGamalMultiRecipientPrivateKey longerPrivateKey = keyPair.getPrivateKey();
		ElGamalMultiRecipientMessage differentMessage = ElGamalMultiRecipientMessage.getMessage(ciphertext, longerPrivateKey);

		assertNotEquals(message, differentMessage);
	}
}
