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

import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

class ElGamalMultiRecipientPrivateKeyTest {

	private static ZqElement validExponent;
	private static ZqGroup validExponentGroup;

	@BeforeAll
	static void setUp() {
		validExponentGroup = new ZqGroup(BigInteger.TEN);
		validExponent = ZqElement.create(BigInteger.valueOf(2), validExponentGroup);
	}

	@Test
	void givenAnExponentOfZeroThenThrows() {
		ZqElement zeroExponent = ZqElement.create(BigInteger.ZERO, validExponentGroup);
		List<ZqElement> exponents = Arrays.asList(validExponent, zeroExponent);
		assertThrows(IllegalArgumentException.class, () -> new ElGamalMultiRecipientPrivateKey(exponents));
	}

	@Test
	void givenAnExponentOfOneThenThrows() {
		ZqElement oneExponent = ZqElement.create(BigInteger.ONE, validExponentGroup);
		List<ZqElement> exponents = Arrays.asList(validExponent, oneExponent);
		assertThrows(IllegalArgumentException.class, () -> new ElGamalMultiRecipientPrivateKey(exponents));
	}
}
