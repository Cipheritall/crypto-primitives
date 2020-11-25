/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.elgamal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.google.common.collect.Streams;

import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;

class ElGamalMultiRecipientKeyPairTest {

	private static GqGroup publicKeyGroup;
	private static ElGamalMultiRecipientKeyPair keyPair;
	private static RandomService randomSer;
	private static int numKeys;
	private static ZqGroup privateKeyGroup;

	@BeforeAll
	static void setUp() {
		BigInteger p = BigInteger.valueOf(23);
		BigInteger q = BigInteger.valueOf(11);
		BigInteger g = BigInteger.valueOf(2);

		publicKeyGroup = new GqGroup(p, q, g);
		privateKeyGroup = ZqGroup.sameOrderAs(publicKeyGroup);

		randomSer = new RandomService();

		numKeys = 10;
		keyPair = ElGamalMultiRecipientKeyPair.genKeyPair(publicKeyGroup, numKeys, randomSer);
	}

	@Test
	void generateFailsOnNullGroup() {
		assertThrows(NullPointerException.class, () -> ElGamalMultiRecipientKeyPair.genKeyPair(null, 10, randomSer));
	}

	@Test
	void generateFailsOnZeroLength() {
		assertThrows(IllegalArgumentException.class, () -> ElGamalMultiRecipientKeyPair.genKeyPair(publicKeyGroup, 0, randomSer));
	}

	@Test
	void generateFailsOnNegativeLength() {
		assertThrows(IllegalArgumentException.class, () -> ElGamalMultiRecipientKeyPair.genKeyPair(publicKeyGroup, -1, randomSer));
	}

	@Test
	void testThatGeneratedKeysSizesAreTheExpectedValues() {
		int numGeneratedPrivateKeys = keyPair.getPrivateKey().toList().size();
		int numGeneratedPublicKeys = keyPair.getPublicKey().toList().size();

		assertEquals(numKeys, numGeneratedPrivateKeys);
		assertEquals(numKeys, numGeneratedPublicKeys);
	}

	@Test
	void testThatGeneratedKeysAreMembersOfTheSpecifiedGroup() {
		assertEquals(publicKeyGroup, keyPair.getPublicKey().getGroup());
		assertEquals(privateKeyGroup, keyPair.getPrivateKey().getGroup());
	}

	@Test
	void testThatPublicKeyCorrespondsToPrivateKey() {
		assertTrue(Streams.zip(
				keyPair.getPrivateKey().toList().stream(),
				keyPair.getPublicKey().toList().stream(),
				(ske, pke) -> publicKeyGroup.getGenerator().exponentiate(ske).equals(pke))
				.allMatch(Boolean::booleanValue));
	}

	/**
	 * Check that the created key pair elements stay within the bounds [2, q). By creating 10 * q elements, the probability of having a false positive
	 * is at most (q/(q+1))^(10*q) which converges towards 1/e^10 ~ 0.00005
	 */
	@Test
	void testThatPrivateKeyExponentsWithinBounds() {
		BigInteger p = BigInteger.valueOf(11);
		BigInteger q = BigInteger.valueOf(5);
		BigInteger g = BigInteger.valueOf(3);
		GqGroup smallGroup = new GqGroup(p, q, g);
		ElGamalMultiRecipientKeyPair keyPair = ElGamalMultiRecipientKeyPair.genKeyPair(smallGroup, 10 * q.intValue(), randomSer);
		keyPair.getPrivateKey().toList().forEach(sk -> {
			assertTrue(sk.getValue().compareTo(BigInteger.valueOf(2)) >= 0);
			assertTrue(sk.getValue().compareTo(q) < 0);
		});
	}
}
