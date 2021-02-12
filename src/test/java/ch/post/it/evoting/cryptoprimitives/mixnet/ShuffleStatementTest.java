/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.SecureRandom;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GqGroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;

@DisplayName("A ShuffleStatement")
class ShuffleStatementTest {

	private static final int KEY_ELEMENTS_NUMBER = 11;
	private static final int RANDOM_UPPER_BOUND = 10;
	private static final SecureRandom secureRandom = new SecureRandom();

	private static GqGroup gqGroup;
	private static ElGamalMultiRecipientPublicKey publicKey;
	private static ElGamalGenerator elGamalGenerator;

	private int n;
	private int l;
	private SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts;
	private SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> shuffledCiphertexts;

	@BeforeAll
	static void setUpAll() {
		gqGroup = GqGroupTestData.getGroup();
		final GqGroupGenerator gqGroupGenerator = new GqGroupGenerator(gqGroup);

		final List<GqElement> pkElements = Stream.generate(gqGroupGenerator::genNonIdentityNonGeneratorMember).limit(KEY_ELEMENTS_NUMBER)
				.collect(Collectors.toList());
		publicKey = new ElGamalMultiRecipientPublicKey(pkElements);

		elGamalGenerator = new ElGamalGenerator(gqGroup);
	}

	@BeforeEach
	void setUp() {
		n = secureRandom.nextInt(RANDOM_UPPER_BOUND) + 1;
		l = secureRandom.nextInt(RANDOM_UPPER_BOUND) + 1;

		ciphertexts = new SameGroupVector<>(elGamalGenerator.genRandomCiphertexts(publicKey, l, n));
		shuffledCiphertexts = new SameGroupVector<>(elGamalGenerator.genRandomCiphertexts(publicKey, l, n));
	}

	@Test
	@DisplayName("with valid parameters gives expected statement")
	void construct() {
		final ShuffleStatement shuffleStatement = new ShuffleStatement(ciphertexts, shuffledCiphertexts);

		assertEquals(gqGroup, shuffleStatement.getCiphertexts().getGroup());
		assertEquals(gqGroup, shuffleStatement.getShuffledCiphertexts().getGroup());
	}

	@Test
	@DisplayName("with any null parameter throws NullPointerException")
	void constructNullParams() {
		assertThrows(NullPointerException.class, () -> new ShuffleStatement(null, shuffledCiphertexts));
		assertThrows(NullPointerException.class, () -> new ShuffleStatement(ciphertexts, null));
	}

	@Test
	@DisplayName("with empty ciphertexts throws IllegalArgumentException")
	void constructEmptyParams() {
		final SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> emptyCiphertexts = SameGroupVector.of();
		final SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> emptyShuffledCiphertexts = SameGroupVector.of();

		final IllegalArgumentException emptyCiphertextsException = assertThrows(IllegalArgumentException.class,
				() -> new ShuffleStatement(emptyCiphertexts, shuffledCiphertexts));
		assertEquals("The ciphertexts vector can not be empty.", emptyCiphertextsException.getMessage());

		final IllegalArgumentException emptyShuffledCiphertextsException = assertThrows(IllegalArgumentException.class,
				() -> new ShuffleStatement(ciphertexts, emptyShuffledCiphertexts));
		assertEquals("The shuffled ciphertexts vector can not be empty.", emptyShuffledCiphertextsException.getMessage());
	}

	@Test
	@DisplayName("with ciphertexts and shuffled ciphertexts of different size throws IllegalArgumentException")
	void constructDiffSizeVectors() {
		final SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> longerCiphertexts = ciphertexts
				.append(elGamalGenerator.genRandomCiphertext(l));

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ShuffleStatement(longerCiphertexts, shuffledCiphertexts));
		assertEquals("The ciphertexts and shuffled ciphertexts vectors must have the same size.", exception.getMessage());
	}

	@Test
	@DisplayName("with not all ciphertexts having the same size throws IllegalArgumentException")
	void constructDiffPhisCiphertexts() {
		final SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> diffPhisCiphertexts = ciphertexts
				.append(elGamalGenerator.genRandomCiphertext(l + 1));
		final SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> longerShuffledCiphertexts = ciphertexts
				.append(elGamalGenerator.genRandomCiphertext(l));

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ShuffleStatement(diffPhisCiphertexts, longerShuffledCiphertexts));
		assertEquals("All ciphertexts must have the same size.", exception.getMessage());
	}

	@Test
	@DisplayName("with not all shuffled ciphertexts having the same size throws IllegalArgumentException")
	void constructDiffPhisShuffledCiphertexts() {
		final SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> longerCiphertexts = ciphertexts
				.append(elGamalGenerator.genRandomCiphertext(l));
		final SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> diffPhisShuffledCiphertexts = ciphertexts
				.append(elGamalGenerator.genRandomCiphertext(l + 1));

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ShuffleStatement(longerCiphertexts, diffPhisShuffledCiphertexts));
		assertEquals("All shuffled ciphertexts must have the same size.", exception.getMessage());
	}

	@Test
	@DisplayName("with ciphertexts and shuffled ciphertexts having different size throws IllegalArgumentException")
	void constructCiphertextsAndShuffledDiffSizePhis() {
		final SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> morePhisCiphertexts = new SameGroupVector<>(
				elGamalGenerator.genRandomCiphertexts(publicKey, l + 1, n));

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ShuffleStatement(morePhisCiphertexts, shuffledCiphertexts));
		assertEquals("The ciphertexts and shuffled ciphertexts must have the same size.", exception.getMessage());
	}

	@Test
	@DisplayName("with ciphertexts and shuffled ciphertexts from different groups throws IllegalArgumentException")
	void constructDiffGroupCiphertextsAndShuffled() {
		// Public key from different group.
		final GqGroup differentGroup = GqGroupTestData.getDifferentGroup(gqGroup);
		final GqGroupGenerator diffGroupGqGroupGenerator = new GqGroupGenerator(differentGroup);
		final List<GqElement> pkElements = Stream.generate(diffGroupGqGroupGenerator::genNonIdentityNonGeneratorMember).limit(KEY_ELEMENTS_NUMBER)
				.collect(Collectors.toList());
		final ElGamalMultiRecipientPublicKey diffGroupPublicKey = new ElGamalMultiRecipientPublicKey(pkElements);

		// Ciphertexts from different group with above key.
		final ElGamalGenerator differentElGamalGenerator = new ElGamalGenerator(differentGroup);
		final SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> diffGroupCiphertexts = new SameGroupVector<>(
				differentElGamalGenerator.genRandomCiphertexts(diffGroupPublicKey, l, n));

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ShuffleStatement(diffGroupCiphertexts, shuffledCiphertexts));
		assertEquals("The ciphertexts and shuffle ciphertexts must be part of the same group.", exception.getMessage());
	}

	@Test
	void testEquals() {
		final ShuffleStatement shuffleStatement1 = new ShuffleStatement(ciphertexts, shuffledCiphertexts);
		final ShuffleStatement shuffleStatement2 = new ShuffleStatement(ciphertexts, shuffledCiphertexts);

		final SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> otherCiphertexts = ciphertexts
				.append(elGamalGenerator.genRandomCiphertext(l));
		final SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> otherShuffledCiphertexts = shuffledCiphertexts
				.append(elGamalGenerator.genRandomCiphertext(l));
		final ShuffleStatement shuffleStatement3 = new ShuffleStatement(otherCiphertexts, otherShuffledCiphertexts);

		assertEquals(shuffleStatement1, shuffleStatement1);
		assertEquals(shuffleStatement1, shuffleStatement2);
		assertNotEquals(shuffleStatement1, shuffleStatement3);
	}

	@Test
	void testHashCode() {
		final ShuffleStatement shuffleStatement1 = new ShuffleStatement(ciphertexts, shuffledCiphertexts);
		final ShuffleStatement shuffleStatement2 = new ShuffleStatement(ciphertexts, shuffledCiphertexts);

		assertEquals(shuffleStatement1, shuffleStatement2);
		assertEquals(shuffleStatement1.hashCode(), shuffleStatement1.hashCode());
		assertEquals(shuffleStatement1.hashCode(), shuffleStatement2.hashCode());
	}
}