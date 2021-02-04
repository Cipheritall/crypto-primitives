package ch.post.it.evoting.cryptoprimitives.mixnet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.SecureRandom;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.SameGroupMatrix;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GqGroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;

class DiagonalProductsTest {

	private static final int KEY_ELEMENTS_NUMBER = 11;
	private static final SecureRandom secureRandom = new SecureRandom();

	private static GqGroup gqGroup;
	private static ZqGroup zqGroup;
	private static ZqGroupGenerator zqGroupGenerator;
	private static GqGroupGenerator gqGroupGenerator;
	private static ElGamalMultiRecipientPublicKey publicKey;
	private static DiagonalProducts diagonalProducts;

	@BeforeAll
	static void setUpAll() {
		// GqGroup and corresponding ZqGroup set up.
		gqGroup = GqGroupTestData.getGroup();
		gqGroupGenerator = new GqGroupGenerator(gqGroup);
		zqGroup = ZqGroup.sameOrderAs(gqGroup);
		zqGroupGenerator = new ZqGroupGenerator(zqGroup);

		final List<GqElement> pkElements = Stream.generate(gqGroupGenerator::genNonIdentityNonGeneratorMember).limit(KEY_ELEMENTS_NUMBER)
				.collect(Collectors.toList());
		publicKey = new ElGamalMultiRecipientPublicKey(pkElements);

		diagonalProducts = new DiagonalProducts(publicKey);
	}

	@Nested
	@DisplayName("getDiagonalProducts")
	class GetDiagonalProducts {

		private static final int RANDOM_UPPER_BOUND = 10;

		private int n;
		private int m;
		private int l;
		private SameGroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts;
		private SameGroupMatrix<ZqElement, ZqGroup> exponents;

		@BeforeEach
		void setUp() {
			n = secureRandom.nextInt(RANDOM_UPPER_BOUND) + 1;
			m = secureRandom.nextInt(RANDOM_UPPER_BOUND) + 1;
			l = secureRandom.nextInt(RANDOM_UPPER_BOUND) + 1;

			// The ciphertexts matrix is a m x n matrix.
			final List<List<ElGamalMultiRecipientCiphertext>> randomCiphertexts = Stream.generate(
					() -> ElGamalGenerator.genRandomCiphertexts(gqGroup, publicKey, l, n))
					.limit(m)
					.collect(Collectors.toList());
			ciphertexts = SameGroupMatrix.fromRows(randomCiphertexts);

			// The exponents matrix is a n x (m + 1) matrix.
			exponents = zqGroupGenerator.generateRandomZqElementMatrix(n, m + 1);
		}

		@Test
		@DisplayName("with valid inputs does not throw")
		void getDiagonalProductsValid() {
			final SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> diagonalProductsOutput = diagonalProducts
					.getDiagonalProducts(ciphertexts, exponents);
			assertEquals(2 * m, diagonalProductsOutput.size());
		}

		@Test
		@DisplayName("with any null parameter throws NullPointerException")
		void getDiagonalProductsNullParams() {
			assertThrows(NullPointerException.class, () -> diagonalProducts.getDiagonalProducts(null, exponents));
			assertThrows(NullPointerException.class, () -> diagonalProducts.getDiagonalProducts(ciphertexts, null));
		}

		@Test
		@DisplayName("with any empty matrix throws IllegalArgumentException")
		void getDiagonalProductsEmptyParams() {
			final SameGroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> emptyCiphertexts = SameGroupMatrix.fromRows(Collections.emptyList());
			final SameGroupMatrix<ZqElement, ZqGroup> emptyExponents = SameGroupMatrix.fromRows(Collections.emptyList());

			final IllegalArgumentException emptyCiphertextsException = assertThrows(IllegalArgumentException.class,
					() -> diagonalProducts.getDiagonalProducts(emptyCiphertexts, exponents));
			assertEquals("The ciphertexts and exponents matrices can not be empty.", emptyCiphertextsException.getMessage());

			final IllegalArgumentException emptyExponentsException = assertThrows(IllegalArgumentException.class,
					() -> diagonalProducts.getDiagonalProducts(ciphertexts, emptyExponents));
			assertEquals("The ciphertexts and exponents matrices can not be empty.", emptyExponentsException.getMessage());
		}

		@Test
		@DisplayName("with exponents having different number of rows throws IllegalArgumentException")
		void getDiagonalProductsExponentsTooManyRows() {
			final SameGroupMatrix<ZqElement, ZqGroup> biggerExponents = zqGroupGenerator.generateRandomZqElementMatrix(n + 1, m + 1);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> diagonalProducts.getDiagonalProducts(ciphertexts, biggerExponents));
			assertEquals("The ciphertexts matrix must have as many columns as the exponents matrix has rows.", exception.getMessage());
		}

		@Test
		@DisplayName("with exponents having wrong number of columns throws IllegalArgumentException")
		void getDiagonalProductsExponentsTooFewRows() {
			final SameGroupMatrix<ZqElement, ZqGroup> lessColsExponents = zqGroupGenerator.generateRandomZqElementMatrix(n, m);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> diagonalProducts.getDiagonalProducts(ciphertexts, lessColsExponents));
			assertEquals("The exponents matrix must have one more column than the ciphertexts matrix has rows.", exception.getMessage());
		}

		@Test
		@DisplayName("with too few public key elements throws IllegalArgumentException")
		void getDiagonalProductsTooFewKeyElements() {
			final List<GqElement> pkElements = Stream.generate(gqGroupGenerator::genNonIdentityNonGeneratorMember).limit(KEY_ELEMENTS_NUMBER + 1)
					.collect(Collectors.toList());
			final ElGamalMultiRecipientPublicKey otherPublicKey = new ElGamalMultiRecipientPublicKey(pkElements);
			final List<List<ElGamalMultiRecipientCiphertext>> randomCiphertexts = Stream.generate(
					() -> ElGamalGenerator.genRandomCiphertexts(gqGroup, otherPublicKey, KEY_ELEMENTS_NUMBER + 1, n))
					.limit(m)
					.collect(Collectors.toList());
			final SameGroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> otherCiphertexts = SameGroupMatrix.fromRows(randomCiphertexts);
			final SameGroupMatrix<ZqElement, ZqGroup> otherExponents = zqGroupGenerator.generateRandomZqElementMatrix(n, m + 1);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> diagonalProducts.getDiagonalProducts(otherCiphertexts, otherExponents));
			assertEquals("There must be at least the same number of key elements than ciphertexts' phis.", exception.getMessage());
		}

		@Test
		@DisplayName("with ciphertexts of different size throws IllegalArgumentException")
		void getDiagonalProductsDifferentSizeCiphertexts() {
			// Create a row with ciphertexts having more phis.
			final List<ElGamalMultiRecipientCiphertext> longerCiphertexts = ElGamalGenerator.genRandomCiphertexts(gqGroup, publicKey, l + 1, n);
			// Convert matrix to a mutable one.
			final List<List<ElGamalMultiRecipientCiphertext>> collect = ciphertexts.rowStream()
					.map(l -> l.stream().collect(Collectors.toList()))
					.collect(Collectors.toList());
			// Add to have at least two rows.
			collect.add(longerCiphertexts);
			final SameGroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> longerCiphertextsMatrix = SameGroupMatrix.fromRows(collect);

			final SameGroupMatrix<ZqElement, ZqGroup> longerExponents = zqGroupGenerator.generateRandomZqElementMatrix(n, m + 2);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> diagonalProducts.getDiagonalProducts(longerCiphertextsMatrix, longerExponents));
			assertEquals("All ciphertexts must have the same number of phis.", exception.getMessage());
		}

		@Test
		@DisplayName("with public key and ciphertexts of different group throws IllegalArgumentException")
		void getDiagonalProductsDifferentGroupKeyAndCiphertexts() {
			// Pick another group.
			final GqGroup differentGroup = GqGroupTestData.getDifferentGroup(gqGroup);
			final GqGroupGenerator differentGqGroupGenerator = new GqGroupGenerator(differentGroup);

			// Generate ciphertexts from different group (a new key is also needed).
			final List<GqElement> pkElements = Stream.generate(differentGqGroupGenerator::genNonIdentityNonGeneratorMember).limit(l)
					.collect(Collectors.toList());
			final ElGamalMultiRecipientPublicKey differentGroupPublicKey = new ElGamalMultiRecipientPublicKey(pkElements);
			final List<List<ElGamalMultiRecipientCiphertext>> otherGroupRandomCiphertexts = Stream.generate(
					() -> ElGamalGenerator.genRandomCiphertexts(differentGroup, differentGroupPublicKey, l, n))
					.limit(m)
					.collect(Collectors.toList());
			final SameGroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> differentGroupCiphertexts = SameGroupMatrix
					.fromRows(otherGroupRandomCiphertexts);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> diagonalProducts.getDiagonalProducts(differentGroupCiphertexts, exponents));
			assertEquals("The public key and ciphertexts matrices must be part of the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("with ciphertexts of different group order than exponents throws IllegalArgumentException")
		void getDiagonalProductsDifferentOrderCiphertextsAndExponents() {
			final ZqGroupGenerator differentZqGroupGenerator = new ZqGroupGenerator(ZqGroup.sameOrderAs(GqGroupTestData.getDifferentGroup(gqGroup)));

			final SameGroupMatrix<ZqElement, ZqGroup> differentGroupExponents = differentZqGroupGenerator.generateRandomZqElementMatrix(n, m + 1);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> diagonalProducts.getDiagonalProducts(ciphertexts, differentGroupExponents));
			assertEquals("The exponents group must have the order of the ciphertexts group.", exception.getMessage());
		}

	}

}