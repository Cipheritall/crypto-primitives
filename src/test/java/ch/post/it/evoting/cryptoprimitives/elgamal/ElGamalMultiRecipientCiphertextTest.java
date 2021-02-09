/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.elgamal;

import static ch.post.it.evoting.cryptoprimitives.SameGroupVector.toSameGroupVector;
import static java.util.stream.Collectors.toList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GqGroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.math.Matrix;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.JsonData;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.TestParameters;

@DisplayName("A ciphertext")
class ElGamalMultiRecipientCiphertextTest {

	private static GqGroup gqGroup;
	private static GqGroupGenerator gqGroupGenerator;

	private static ImmutableList<GqElement> validPhis;
	private static GqElement validGamma;

	@BeforeAll
	static void setUpAll() {
		gqGroup = GqGroupTestData.getGroup();
		gqGroupGenerator = new GqGroupGenerator(gqGroup);
	}

	@BeforeEach
	void setUp() {
		// Generate valid phis.
		final GqElement ge1 = gqGroupGenerator.genMember();
		final GqElement ge2 = gqGroupGenerator.genMember();

		validPhis = ImmutableList.of(ge1, ge2);

		// Generate a valid gamma.
		do {
			validGamma = gqGroupGenerator.genNonIdentityMember();
		} while (validGamma.equals(gqGroup.getGenerator()));
	}

	@Test
	@DisplayName("contains the correct gamma and phis")
	void constructionTest() {
		final ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertext.create(validGamma, validPhis);
		assertEquals(validGamma, ciphertext.getGamma());
		assertEquals(validPhis, ciphertext.stream().collect(toList()));
	}

	// Provides parameters for the withInvalidParameters test.
	static Stream<Arguments> createArgumentsProvider() {

		final List<GqElement> invalidPhis = Arrays.asList(GqElement.create(BigInteger.ONE, gqGroup), null);

		final GqGroup differentGroup = GqGroupTestData.getDifferentGroup(gqGroup);
		final GqGroupGenerator differentGenerator = new GqGroupGenerator(differentGroup);
		final List<GqElement> differentGroupPhis = Arrays.asList(gqGroupGenerator.genMember(), differentGenerator.genMember());

		final GqElement otherGroupGamma = genOtherGroupGamma(differentGroup);

		return Stream.of(
				Arguments.of(null, validPhis, NullPointerException.class),
				Arguments.of(validGamma, null, NullPointerException.class),
				Arguments.of(validGamma, Collections.emptyList(), IllegalArgumentException.class),
				Arguments.of(validGamma, invalidPhis, IllegalArgumentException.class),
				Arguments.of(validGamma, differentGroupPhis, IllegalArgumentException.class),
				Arguments.of(otherGroupGamma, validPhis, IllegalArgumentException.class)
		);
	}

	@ParameterizedTest(name = "gamma = {0} and phis = {1} throws {2}")
	@MethodSource("createArgumentsProvider")
	@DisplayName("created with invalid parameters")
	void withInvalidParameters(final GqElement gamma, final List<GqElement> phis, final Class<? extends RuntimeException> exceptionClass) {
		assertThrows(exceptionClass, () -> ElGamalMultiRecipientCiphertext.create(gamma, phis));
	}

	@Test
	@DisplayName("has valid equals for gamma")
	void gammaEqualsTest() {
		final GqElement differentGamma = genDifferentGamma();

		final ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertext.create(validGamma, validPhis);
		final ElGamalMultiRecipientCiphertext sameCiphertext = ElGamalMultiRecipientCiphertext.create(validGamma, validPhis);
		final ElGamalMultiRecipientCiphertext differentCiphertext = ElGamalMultiRecipientCiphertext.create(differentGamma, validPhis);

		assertEquals(ciphertext, sameCiphertext);
		assertNotEquals(ciphertext, differentCiphertext);
	}

	@Test
	@DisplayName("has valid equals for the phis")
	void phisEqualsTest() {
		final List<GqElement> differentPhis = genDifferentPhis();

		final ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertext.create(validGamma, validPhis);
		final ElGamalMultiRecipientCiphertext sameCiphertext = ElGamalMultiRecipientCiphertext.create(validGamma, validPhis);
		final ElGamalMultiRecipientCiphertext differentCiphertext = ElGamalMultiRecipientCiphertext.create(validGamma, differentPhis);

		assertEquals(ciphertext, sameCiphertext);
		assertNotEquals(ciphertext, differentCiphertext);
	}

	@Test
	@DisplayName("has valid hashCode")
	void hashCodeTest() {
		final GqElement differentGamma = genDifferentGamma();

		final ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertext.create(validGamma, validPhis);
		final ElGamalMultiRecipientCiphertext sameCiphertext = ElGamalMultiRecipientCiphertext.create(validGamma, validPhis);
		final ElGamalMultiRecipientCiphertext differentCiphertext = ElGamalMultiRecipientCiphertext.create(differentGamma, validPhis);

		assertEquals(ciphertext.hashCode(), sameCiphertext.hashCode());
		assertNotEquals(ciphertext.hashCode(), differentCiphertext.hashCode());
	}

	@Test
	@DisplayName("as neutral element contains only 1s")
	void neutralElementTest() {
		int n = new SecureRandom().nextInt(10) + 1;
		ElGamalMultiRecipientCiphertext neutralElement = ElGamalMultiRecipientCiphertext.neutralElement(n, gqGroup);

		GqElement one = gqGroup.getIdentity();
		List<GqElement> ones = Stream.generate(() -> one).limit(n).collect(toList());

		assertEquals(one, neutralElement.getGamma());
		assertEquals(ones, neutralElement.stream().collect(toList()));
		assertEquals(n, neutralElement.size());
	}

	@Test
	@DisplayName("as neutral element with size 0 throws an IllegalArgumentException")
	void neutralElementWithSizeZero() {
		Exception exception = assertThrows(IllegalArgumentException.class, () -> ElGamalMultiRecipientCiphertext.neutralElement(0, gqGroup));
		assertEquals("The neutral ciphertext must have at least one phi.", exception.getMessage());
	}

	@Test
	@DisplayName("as neutral element with null group throws a NullPointerException")
	void neutralElementWithNullGroupTest() {
		assertThrows(NullPointerException.class, () -> ElGamalMultiRecipientCiphertext.neutralElement(1, null));
	}

	private static GqElement genOtherGroupGamma(final GqGroup otherGroup) {
		final GqGroupGenerator otherGroupGenerator = new GqGroupGenerator(otherGroup);

		GqElement otherGroupGamma;
		do {
			otherGroupGamma = otherGroupGenerator.genNonIdentityMember();
		} while (otherGroupGamma.equals(otherGroup.getGenerator()));
		return otherGroupGamma;
	}

	private GqElement genDifferentGamma() {
		GqElement differentGamma;
		do {
			differentGamma = gqGroupGenerator.genNonIdentityMember();
		} while (differentGamma.equals(validGamma) || differentGamma.equals(gqGroup.getGenerator()));
		return differentGamma;
	}

	private List<GqElement> genDifferentPhis() {
		List<GqElement> differentPhis;
		do {
			differentPhis = Arrays.asList(gqGroupGenerator.genMember(), gqGroupGenerator.genMember());
		} while (differentPhis.equals(validPhis));
		return differentPhis;
	}

	private List<GqElement> genOtherGroupPhis(final GqGroup otherGroup) {
		final GqGroupGenerator otherGroupGenerator = new GqGroupGenerator(otherGroup);

		return Arrays.asList(otherGroupGenerator.genMember(), otherGroupGenerator.genMember());
	}

	// ===============================================================================================================================================
	// Multiplication tests.
	// ===============================================================================================================================================

	// Provides parameters for the multiplyTest.
	static Stream<Arguments> jsonFileArgumentProvider() {

		final List<TestParameters> parametersList = TestParameters.fromResource("/elgamal/get-ciphertext-product.json");

		return parametersList.stream().parallel().map(testParameters -> {
			// Context.
			final JsonData egJsonData = testParameters.getContext().getJsonData("eg");
			final BigInteger p = egJsonData.get("p", BigInteger.class);
			final BigInteger q = egJsonData.get("q", BigInteger.class);
			final BigInteger g = testParameters.getContext().get("g", BigInteger.class);

			final GqGroup group = new GqGroup(p, q, g);

			// Parse first ciphertext parameters.
			final JsonData upperCa = testParameters.getInput().getJsonData("upper_c_a");

			final GqElement gammaA = GqElement.create(upperCa.get("gamma", BigInteger.class), group);
			final BigInteger[] phisAArray = upperCa.get("phis", BigInteger[].class);
			final List<GqElement> phisA = Arrays.stream(phisAArray).map(phiA -> GqElement.create(phiA, group)).collect(toList());

			// Parse second ciphertext parameters.
			final JsonData upperCb = testParameters.getInput().getJsonData("upper_c_b");

			final GqElement gammaB = GqElement.create(upperCb.get("gamma", BigInteger.class), group);
			final BigInteger[] phisBArray = upperCb.get("phis", BigInteger[].class);
			final List<GqElement> phisB = Arrays.stream(phisBArray).map(phi -> GqElement.create(phi, group)).collect(toList());

			// Parse multiplication result parameters.
			final JsonData outputJsonData = testParameters.getOutput();

			final GqElement gammaRes = GqElement.create(outputJsonData.get("gamma", BigInteger.class), group);
			final BigInteger[] phisOutput = outputJsonData.get("phis", BigInteger[].class);
			final List<GqElement> phisRes = Arrays.stream(phisOutput).map(phi -> GqElement.create(phi, group)).collect(toList());

			return Arguments.of(gammaA, phisA, gammaB, phisB, gammaRes, phisRes, testParameters.getDescription());
		});
	}

	@ParameterizedTest
	@MethodSource("jsonFileArgumentProvider")
	@DisplayName("with a valid other ciphertext gives expected result")
	void multiplyWithRealValuesTest(final GqElement gammaA, final List<GqElement> phisA, final GqElement gammaB, final List<GqElement> phisB,
			final GqElement gammaRes, final List<GqElement> phisRes, final String description) {

		// Create first ciphertext.
		final ElGamalMultiRecipientCiphertext ciphertextA = ElGamalMultiRecipientCiphertext.create(gammaA, phisA);

		// Create second ciphertext.
		final ElGamalMultiRecipientCiphertext ciphertextB = ElGamalMultiRecipientCiphertext.create(gammaB, phisB);

		// Expected multiplication result.
		final ElGamalMultiRecipientCiphertext ciphertextRes = ElGamalMultiRecipientCiphertext.create(gammaRes, phisRes);

		assertEquals(ciphertextRes, ciphertextA.multiply(ciphertextB), String.format("assertion failed for: %s", description));
	}

	@Test
	void multiplyTest() {
		final GqGroup group = new GqGroup(BigInteger.valueOf(11), BigInteger.valueOf(5), BigInteger.valueOf(3));

		// Create first ciphertext.
		final GqElement gammaA = GqElement.create(BigInteger.valueOf(4), group);
		final List<GqElement> phisA = Arrays
				.asList(GqElement.create(BigInteger.valueOf(3), group), GqElement.create(BigInteger.valueOf(5), group));
		final ElGamalMultiRecipientCiphertext ciphertextA = ElGamalMultiRecipientCiphertext.create(gammaA, phisA);

		// Create second ciphertext.
		final GqElement gammaB = GqElement.create(BigInteger.valueOf(5), group);
		final List<GqElement> phisB = Arrays
				.asList(GqElement.create(BigInteger.valueOf(9), group), GqElement.create(BigInteger.valueOf(1), group));
		final ElGamalMultiRecipientCiphertext ciphertextB = ElGamalMultiRecipientCiphertext.create(gammaB, phisB);

		// Expected multiplication result.
		final GqElement gammaRes = GqElement.create(BigInteger.valueOf(9), group);
		final List<GqElement> phisRes = Arrays.asList(GqElement.create(BigInteger.valueOf(5), group), GqElement.create(BigInteger.valueOf(5),
				group));
		final ElGamalMultiRecipientCiphertext ciphertextRes = ElGamalMultiRecipientCiphertext.create(gammaRes, phisRes);

		assertEquals(ciphertextRes, ciphertextA.multiply(ciphertextB));
	}

	@Test
	@DisplayName("with an identity ciphertext (1, 1, 1) yields the same ciphertext")
	void multiplyWithIdentityTest() {
		final GqGroup group = GqGroupTestData.getGroup();
		GqGroupGenerator generator = new GqGroupGenerator(group);
		GqElement element1 = generator.genMember();
		GqElement element2 = generator.genMember();

		// Create first ciphertext.
		ElGamalMultiRecipientMessage message = new ElGamalMultiRecipientMessage(Arrays.asList(element1, element2));
		RandomService randomService = new RandomService();
		ZqElement exponent = randomService.genRandomExponent(ZqGroup.sameOrderAs(group));
		ElGamalMultiRecipientPublicKey publicKey = ElGamalMultiRecipientKeyPair.genKeyPair(group, 2, randomService).getPublicKey();
		final ElGamalMultiRecipientCiphertext ciphertextA = ElGamalMultiRecipientCiphertext.getCiphertext(message, exponent, publicKey);

		// Create identity ciphertext.
		final ElGamalMultiRecipientCiphertext ciphertextIdentity = ElGamalMultiRecipientCiphertext.neutralElement(2, group);

		assertEquals(ciphertextA, ciphertextA.multiply(ciphertextIdentity));
	}

	@Test
	@DisplayName("with a null ciphertext throws NullPointerException")
	void multiplyWithNullOtherShouldThrow() {
		final ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertext.create(validGamma, validPhis);

		assertThrows(NullPointerException.class, () -> ciphertext.multiply(null));
	}

	@Test
	@DisplayName("with a ciphertext from another group throws IllegalArgumentException")
	void multiplyWithDifferentGroupOtherShouldThrow() {
		final ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertext.create(validGamma, validPhis);

		final GqGroup otherGroup = new GqGroup(BigInteger.valueOf(7), BigInteger.valueOf(3), BigInteger.valueOf(2));
		final GqElement otherGroupGamma = genOtherGroupGamma(otherGroup);
		final List<GqElement> otherGroupPhis = genOtherGroupPhis(otherGroup);
		final ElGamalMultiRecipientCiphertext other = ElGamalMultiRecipientCiphertext.create(otherGroupGamma, otherGroupPhis);

		assertThrows(IllegalArgumentException.class, () -> ciphertext.multiply(other));
	}

	@Test
	@DisplayName("with a ciphertext with a different number of phis throws IllegalArgumentException")
	void multiplyWithDifferentSizePhisShouldThrow() {
		final ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertext.create(validGamma, validPhis);

		final ImmutableList<GqElement> differentSizePhis = ImmutableList.of(validPhis.get(0));
		final ElGamalMultiRecipientCiphertext other = ElGamalMultiRecipientCiphertext.create(validGamma, differentSizePhis);

		assertThrows(IllegalArgumentException.class, () -> ciphertext.multiply(other));
	}

	@Test
	@DisplayName("exponentiate the ciphertext")
	void decryptedExponentiatedCiphertextAndExponentiatedMessageShouldBeEqual() {
		int noOfMessageElements = 5;
		RandomService randomService = new RandomService();

		ZqElement exponent = randomService.genRandomExponent(ZqGroup.sameOrderAs(gqGroup));
		ElGamalMultiRecipientMessage originalMessage = ElGamalGenerator.genRandomMessage(gqGroupGenerator, noOfMessageElements);
		ElGamalMultiRecipientKeyPair keyPair = ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, noOfMessageElements, randomService);
		ElGamalMultiRecipientCiphertext ciphertext = ElGamalGenerator.encryptMessage(originalMessage, keyPair, gqGroup);

		ElGamalMultiRecipientCiphertext exponentiatedCiphertext = ciphertext.exponentiate(exponent);
		ElGamalMultiRecipientMessage decryptedExponentiatedCipherText = ElGamalMultiRecipientMessage
				.getMessage(exponentiatedCiphertext, keyPair.getPrivateKey());

		List<GqElement> exponentiatedOriginalMessageElements = originalMessage.stream()
				.map(e -> e.exponentiate(exponent))
				.collect(toList());

		ElGamalMultiRecipientMessage exponentiatedOriginalMessage = new ElGamalMultiRecipientMessage(exponentiatedOriginalMessageElements);

		assertEquals(exponentiatedOriginalMessage, decryptedExponentiatedCipherText);
	}

	@Test
	@DisplayName("test vector ciphertext exponentiation")
	void compressedExponentiatedMessagesShouldEqualDecryptedExponentiatedCiphertextVector() {
		int noOfMessageElements = 5;
		RandomService randomService = new RandomService();

		List<ElGamalMultiRecipientMessage> originalMessages = Stream
				.generate(() -> ElGamalGenerator.genRandomMessage(gqGroupGenerator, noOfMessageElements))
				.limit(noOfMessageElements)
				.collect(toList());

		ElGamalMultiRecipientKeyPair keyPair = ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, noOfMessageElements, randomService);

		SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> elGamalMultiRecipientCiphertexts = originalMessages.stream()
				.map(originalMessage -> ElGamalGenerator.encryptMessage(originalMessage, keyPair, gqGroup))
				.collect(toSameGroupVector());

		SameGroupVector<ZqElement, ZqGroup> exponents = Stream
				.generate(() -> randomService.genRandomExponent(ZqGroup.sameOrderAs(gqGroup)))
				.limit(elGamalMultiRecipientCiphertexts.size())
				.collect(toSameGroupVector());

		ElGamalMultiRecipientCiphertext ciphertextVectorExponentiation = ElGamalMultiRecipientCiphertext
				.getCiphertextVectorExponentiation(elGamalMultiRecipientCiphertexts, exponents);

		ElGamalMultiRecipientMessage decryptedExponentiatedCipherText =
				ElGamalMultiRecipientMessage.getMessage(ciphertextVectorExponentiation, keyPair.getPrivateKey());

		List<List<BigInteger>> exponentiatedOriginalMessageElements = IntStream.range(0, originalMessages.size())
				.mapToObj(i -> originalMessages.get(i).stream().map(m -> m.exponentiate(exponents.get(i)).getValue()).collect(toList()))
				.collect(toList());

		List<GqElement> reducedOriginalMessageElements = Matrix.transpose(exponentiatedOriginalMessageElements)
				.stream()
				.map(a -> a.stream()
						.map(b -> GqElement.create(b, gqGroup))
						.reduce(GqElement::multiply))
				.map(Optional::get)
				.collect(toList());

		ElGamalMultiRecipientMessage exponentiatedOriginalMessage = new ElGamalMultiRecipientMessage(reducedOriginalMessageElements);

		assertEquals(exponentiatedOriginalMessage, decryptedExponentiatedCipherText);
	}

	@Test
	void testCiphertextVectorExponentiationNullAndEmptyParameterValidation() {

		SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> emptyCipherTexts = SameGroupVector.of();
		SameGroupVector<ZqElement, ZqGroup> emptyExponents = SameGroupVector.of();

		assertThrows(NullPointerException.class, () -> ElGamalMultiRecipientCiphertext.getCiphertextVectorExponentiation(null, emptyExponents));
		assertThrows(NullPointerException.class, () -> ElGamalMultiRecipientCiphertext.getCiphertextVectorExponentiation(emptyCipherTexts, null));

		IllegalArgumentException emptyIllegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> ElGamalMultiRecipientCiphertext.getCiphertextVectorExponentiation(emptyCipherTexts, emptyExponents));

		assertEquals("Ciphertexts should not be empty", emptyIllegalArgumentException.getMessage());
	}

	@Test
	void testCiphertextVectorExponentiationParameterValidation() {
		int noOfMessageElements = 5;
		RandomService randomService = new RandomService();

		List<ElGamalMultiRecipientMessage> originalMessages = Stream
				.generate(() -> ElGamalGenerator.genRandomMessage(gqGroupGenerator, noOfMessageElements))
				.limit(noOfMessageElements)
				.collect(toList());

		SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> fiveCipherTexts = originalMessages.stream()
				.map(originalMessage -> ElGamalGenerator
						.encryptMessage(originalMessage, ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, originalMessage.size(), randomService),
								gqGroup))
				.collect(toSameGroupVector());

		SameGroupVector<ZqElement, ZqGroup> fourExponents = Stream
				.generate(() -> randomService.genRandomExponent(ZqGroup.sameOrderAs(gqGroup)))
				.limit(fiveCipherTexts.size() - 1)
				.collect(toSameGroupVector());

		IllegalArgumentException sizeIllegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> ElGamalMultiRecipientCiphertext.getCiphertextVectorExponentiation(fiveCipherTexts, fourExponents));

		assertEquals("There should be a matching ciphertext for every exponent.", sizeIllegalArgumentException.getMessage());

		SameGroupVector<ElGamalMultiRecipientMessage, GqGroup> unevenNumberOfMessageElements = IntStream.range(1, noOfMessageElements)
				.mapToObj(i -> ElGamalGenerator.genRandomMessage(gqGroupGenerator, i))
				.limit(noOfMessageElements)
				.collect(toSameGroupVector());

		SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> unevenNumberOfCipherTextElements = IntStream.range(1, noOfMessageElements)
				.mapToObj(i -> ElGamalGenerator.encryptMessage(unevenNumberOfMessageElements.get(i - 1),
						ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, i + 1, randomService), gqGroup))
				.collect(toSameGroupVector());

		IllegalArgumentException unevenIllegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> ElGamalMultiRecipientCiphertext.getCiphertextVectorExponentiation(unevenNumberOfCipherTextElements, fourExponents));
		assertEquals("All ciphertexts must have the same number of phi elements", unevenIllegalArgumentException.getMessage());

		GqGroup differentgqGroup = GqGroupTestData.getDifferentGroup(gqGroup);

		SameGroupVector<ZqElement, ZqGroup> fiveExponents = Stream
				.generate(() -> randomService.genRandomExponent(ZqGroup.sameOrderAs(differentgqGroup)))
				.limit(fiveCipherTexts.size())
				.collect(toSameGroupVector());

		IllegalArgumentException differentQIllegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> ElGamalMultiRecipientCiphertext.getCiphertextVectorExponentiation(fiveCipherTexts, fiveExponents));
		assertEquals("Ciphertexts and exponents must be of the same group.", differentQIllegalArgumentException.getMessage());

	}
}
