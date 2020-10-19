/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.elgamal;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;

class ElGamalMultiRecipientPublicKeyTest {

	private static GqElement validElement;
	private static GqGroup validElementGroup;

	@BeforeAll
	static void setUp() {
		validElementGroup = new GqGroup(BigInteger.valueOf(23), BigInteger.valueOf(11), BigInteger.valueOf(2));
		validElement = GqElement.create(BigInteger.valueOf(4), validElementGroup);
	}

	@Test
	void givenAnKeyElementOfOneThenThrows() {
		GqElement oneKeyElement = GqElement.create(BigInteger.ONE, validElementGroup);
		List<GqElement> exponents = Arrays.asList(validElement, oneKeyElement);
		assertThrows(IllegalArgumentException.class, () -> new ElGamalMultiRecipientPublicKey(exponents));
	}

	@Test
	void givenAnKeyElementEqualToGeneratorThenThrows() {
		GqElement generatorKeyElement = GqElement.create(validElementGroup.getGenerator().getValue(), validElementGroup);
		List<GqElement> exponents = Arrays.asList(validElement, generatorKeyElement);
		assertThrows(IllegalArgumentException.class, () -> new ElGamalMultiRecipientPublicKey(exponents));
	}
}
