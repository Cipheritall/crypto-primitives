package ch.post.it.evoting.cryptoprimitives.mixnet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.HashService;
import ch.post.it.evoting.cryptoprimitives.SameGroupMatrix;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;

class DiagonalProductsTest extends TestGroupSetup {

	private static final int KEY_SIZE = 10;

	private static ElGamalMultiRecipientPublicKey publicKey;
	private static MultiExponentiationArgumentService multiExponentiationArgumentService;
	private static ElGamalGenerator elGamalGenerator;

	private int n;
	private int m;
	private int l;
	private SameGroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts;
	private SameGroupMatrix<ZqElement, ZqGroup> exponents;

	@BeforeAll
	static void setUpAll() throws NoSuchAlgorithmException {
		elGamalGenerator = new ElGamalGenerator(gqGroup);
		publicKey = elGamalGenerator.genRandomPublicKey(KEY_SIZE);

		CommitmentKeyGenerator ckGenerator = new CommitmentKeyGenerator(gqGroup);
		CommitmentKey commitmentKey = ckGenerator.genCommitmentKey(KEY_SIZE);
		HashService hashService = new HashService(MessageDigest.getInstance("SHA-256"));
		multiExponentiationArgumentService = new MultiExponentiationArgumentService(publicKey, commitmentKey, new RandomService(), hashService);

	}

	@BeforeEach
	void setUp() {
		n = secureRandom.nextInt(KEY_SIZE) + 1;
		m = secureRandom.nextInt(KEY_SIZE) + 1;
		l = secureRandom.nextInt(KEY_SIZE) + 1;

		// The ciphertexts matrix is a m x n matrix.
		ciphertexts = elGamalGenerator.genRandomCiphertextMatrix(m, n, l);

		// The exponents matrix is a n x (m + 1) matrix.
		exponents = zqGroupGenerator.genRandomZqElementMatrix(n, m + 1);
	}

	@Test
	@DisplayName("with valid inputs does not throw")
	void getDiagonalProductsValid() {
		final SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> diagonalProductsOutput = multiExponentiationArgumentService
				.getDiagonalProducts(ciphertexts, exponents);
		assertEquals(2 * m, diagonalProductsOutput.size());
	}

	@Test
	@DisplayName("with any null parameter throws NullPointerException")
	void getDiagonalProductsNullParams() {
		assertThrows(NullPointerException.class, () -> multiExponentiationArgumentService.getDiagonalProducts(null, exponents));
		assertThrows(NullPointerException.class, () -> multiExponentiationArgumentService.getDiagonalProducts(ciphertexts, null));
	}

	@Test
	@DisplayName("with any empty matrix throws IllegalArgumentException")
	void getDiagonalProductsEmptyParams() {
		final SameGroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> emptyCiphertexts = SameGroupMatrix.fromRows(Collections.emptyList());
		final SameGroupMatrix<ZqElement, ZqGroup> emptyExponents = SameGroupMatrix.fromRows(Collections.emptyList());

		final IllegalArgumentException emptyCiphertextsException = assertThrows(IllegalArgumentException.class,
				() -> multiExponentiationArgumentService.getDiagonalProducts(emptyCiphertexts, exponents));
		assertEquals("The ciphertexts and exponents matrices can not be empty.", emptyCiphertextsException.getMessage());

		final IllegalArgumentException emptyExponentsException = assertThrows(IllegalArgumentException.class,
				() -> multiExponentiationArgumentService.getDiagonalProducts(ciphertexts, emptyExponents));
		assertEquals("The ciphertexts and exponents matrices can not be empty.", emptyExponentsException.getMessage());
	}

	@Test
	@DisplayName("with exponents having different number of rows throws IllegalArgumentException")
	void getDiagonalProductsExponentsTooManyRows() {
		final SameGroupMatrix<ZqElement, ZqGroup> biggerExponents = zqGroupGenerator.genRandomZqElementMatrix(n + 1, m + 1);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> multiExponentiationArgumentService.getDiagonalProducts(ciphertexts, biggerExponents));
		assertEquals("The ciphertexts matrix must have as many columns as the exponents matrix has rows.", exception.getMessage());
	}

	@Test
	@DisplayName("with exponents having wrong number of columns throws IllegalArgumentException")
	void getDiagonalProductsExponentsTooFewRows() {
		final SameGroupMatrix<ZqElement, ZqGroup> lessColsExponents = zqGroupGenerator.genRandomZqElementMatrix(n, m);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> multiExponentiationArgumentService.getDiagonalProducts(ciphertexts, lessColsExponents));
		assertEquals("The exponents matrix must have one more column than the ciphertexts matrix has rows.", exception.getMessage());
	}

	@Test
	@DisplayName("with too few public key elements throws IllegalArgumentException")
	void getDiagonalProductsTooFewKeyElements() {
		final List<GqElement> pkElements = Stream.generate(gqGroupGenerator::genNonIdentityNonGeneratorMember).limit(KEY_SIZE + 1)
				.collect(Collectors.toList());
		final ElGamalMultiRecipientPublicKey otherPublicKey = new ElGamalMultiRecipientPublicKey(pkElements);
		final List<List<ElGamalMultiRecipientCiphertext>> randomCiphertexts = Stream.generate(
				() -> elGamalGenerator.genRandomCiphertexts(otherPublicKey, KEY_SIZE + 1, n))
				.limit(m)
				.collect(Collectors.toList());
		final SameGroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> otherCiphertexts = SameGroupMatrix.fromRows(randomCiphertexts);
		final SameGroupMatrix<ZqElement, ZqGroup> otherExponents = zqGroupGenerator.genRandomZqElementMatrix(n, m + 1);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> multiExponentiationArgumentService.getDiagonalProducts(otherCiphertexts, otherExponents));
		assertEquals("There must be at least the same number of key elements than ciphertexts' phis.", exception.getMessage());
	}

	@Test
	@DisplayName("with ciphertexts of different size throws IllegalArgumentException")
	void getDiagonalProductsDifferentSizeCiphertexts() {
		// Create a row with ciphertexts having more phis.
		ElGamalMultiRecipientPublicKey longerPublicKey = elGamalGenerator.genRandomPublicKey(l + 1);
		final List<ElGamalMultiRecipientCiphertext> longerCiphertexts = elGamalGenerator.genRandomCiphertexts(longerPublicKey, l + 1, n);
		// Convert matrix to a mutable one.
		final List<List<ElGamalMultiRecipientCiphertext>> collect = ciphertexts.rowStream()
				.map(l -> l.stream().collect(Collectors.toList()))
				.collect(Collectors.toList());
		// Add to have at least two rows.
		collect.add(longerCiphertexts);
		final SameGroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> longerCiphertextsMatrix = SameGroupMatrix.fromRows(collect);

		final SameGroupMatrix<ZqElement, ZqGroup> longerExponents = zqGroupGenerator.genRandomZqElementMatrix(n, m + 2);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> multiExponentiationArgumentService.getDiagonalProducts(longerCiphertextsMatrix, longerExponents));
		assertEquals("All ciphertexts must have the same number of phis.", exception.getMessage());
	}

	@Test
	@DisplayName("with public key and ciphertexts of different group throws IllegalArgumentException")
	void getDiagonalProductsDifferentGroupKeyAndCiphertexts() {
		// Pick another group.
		final GqGroup differentGroup = GroupTestData.getDifferentGqGroup(gqGroup);
		final GqGroupGenerator differentGqGroupGenerator = new GqGroupGenerator(differentGroup);

		// Generate ciphertexts from different group (a new key is also needed).
		final List<GqElement> pkElements = Stream.generate(differentGqGroupGenerator::genNonIdentityNonGeneratorMember).limit(l)
				.collect(Collectors.toList());
		final ElGamalMultiRecipientPublicKey differentGroupPublicKey = new ElGamalMultiRecipientPublicKey(pkElements);
		ElGamalGenerator elGamalGenerator = new ElGamalGenerator(differentGroup);
		final List<List<ElGamalMultiRecipientCiphertext>> otherGroupRandomCiphertexts = Stream.generate(
				() -> elGamalGenerator.genRandomCiphertexts(differentGroupPublicKey, l, n))
				.limit(m)
				.collect(Collectors.toList());
		final SameGroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> differentGroupCiphertexts = SameGroupMatrix
				.fromRows(otherGroupRandomCiphertexts);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> multiExponentiationArgumentService.getDiagonalProducts(differentGroupCiphertexts, exponents));
		assertEquals("The public key and ciphertexts matrices must be part of the same group.", exception.getMessage());
	}

	@Test
	@DisplayName("with ciphertexts of different group order than exponents throws IllegalArgumentException")
	void getDiagonalProductsDifferentOrderCiphertextsAndExponents() {
		final ZqGroupGenerator differentZqGroupGenerator = new ZqGroupGenerator(GroupTestData.getDifferentZqGroup(zqGroup));

		final SameGroupMatrix<ZqElement, ZqGroup> differentGroupExponents = differentZqGroupGenerator.genRandomZqElementMatrix(n, m + 1);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> multiExponentiationArgumentService.getDiagonalProducts(ciphertexts, differentGroupExponents));
		assertEquals("The exponents group must have the order of the ciphertexts group.", exception.getMessage());
	}

}