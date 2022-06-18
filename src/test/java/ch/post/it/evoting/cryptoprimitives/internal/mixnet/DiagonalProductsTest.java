/*
 * Copyright 2022 Post CH Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ch.post.it.evoting.cryptoprimitives.internal.mixnet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.internal.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.internal.hashing.TestHashService;
import ch.post.it.evoting.cryptoprimitives.internal.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqElement.GqElementFactory;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupMatrix;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;

class DiagonalProductsTest extends TestGroupSetup {

	private static final int KEY_SIZE = 10;

	private static MultiExponentiationArgumentService multiExponentiationArgumentService;
	private static ElGamalGenerator elGamalGenerator;

	private int n;
	private int m;
	private int l;
	private GroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts;
	private GroupMatrix<ZqElement, ZqGroup> exponents;

	@BeforeAll
	static void setUpAll() {
		elGamalGenerator = new ElGamalGenerator(gqGroup);
		final ElGamalMultiRecipientPublicKey publicKey = elGamalGenerator.genRandomPublicKey(KEY_SIZE);

		final TestCommitmentKeyGenerator ckGenerator = new TestCommitmentKeyGenerator(gqGroup);
		final CommitmentKey commitmentKey = ckGenerator.genCommitmentKey(KEY_SIZE);
		final HashService hashService = TestHashService.create(gqGroup.getQ());
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
		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> diagonalProductsOutput = multiExponentiationArgumentService
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
	@DisplayName("with exponents having different number of rows throws IllegalArgumentException")
	void getDiagonalProductsExponentsTooManyRows() {
		final GroupMatrix<ZqElement, ZqGroup> biggerExponents = zqGroupGenerator.genRandomZqElementMatrix(n + 1, m + 1);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> multiExponentiationArgumentService.getDiagonalProducts(ciphertexts, biggerExponents));
		assertEquals("The ciphertexts matrix must have as many columns as the exponents matrix has rows.", exception.getMessage());
	}

	@Test
	@DisplayName("with exponents having wrong number of columns throws IllegalArgumentException")
	void getDiagonalProductsExponentsTooFewRows() {
		final GroupMatrix<ZqElement, ZqGroup> lessColsExponents = zqGroupGenerator.genRandomZqElementMatrix(n, m);

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
		final GroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> otherCiphertexts = GroupMatrix.fromRows(randomCiphertexts);
		final GroupMatrix<ZqElement, ZqGroup> otherExponents = zqGroupGenerator.genRandomZqElementMatrix(n, m + 1);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> multiExponentiationArgumentService.getDiagonalProducts(otherCiphertexts, otherExponents));
		assertEquals("There must be at least the same number of key elements than ciphertexts' phis.", exception.getMessage());
	}

	@Test
	@DisplayName("with public key and ciphertexts of different group throws IllegalArgumentException")
	void getDiagonalProductsDifferentGroupKeyAndCiphertexts() {
		// Generate ciphertexts from different group (a new key is also needed).
		final List<GqElement> pkElements = Stream.generate(otherGqGroupGenerator::genNonIdentityNonGeneratorMember).limit(l)
				.collect(Collectors.toList());
		final ElGamalMultiRecipientPublicKey differentGroupPublicKey = new ElGamalMultiRecipientPublicKey(pkElements);
		final ElGamalGenerator elGamalGenerator = new ElGamalGenerator(otherGqGroup);
		final List<List<ElGamalMultiRecipientCiphertext>> otherGroupRandomCiphertexts = Stream.generate(
						() -> elGamalGenerator.genRandomCiphertexts(differentGroupPublicKey, l, n))
				.limit(m)
				.collect(Collectors.toList());
		final GroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> differentGroupCiphertexts = GroupMatrix
				.fromRows(otherGroupRandomCiphertexts);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> multiExponentiationArgumentService.getDiagonalProducts(differentGroupCiphertexts, exponents));
		assertEquals("The public key and ciphertexts matrices must be part of the same group.", exception.getMessage());
	}

	@Test
	@DisplayName("with ciphertexts of different group order than exponents throws IllegalArgumentException")
	void getDiagonalProductsDifferentOrderCiphertextsAndExponents() {
		final GroupMatrix<ZqElement, ZqGroup> differentGroupExponents = otherZqGroupGenerator.genRandomZqElementMatrix(n, m + 1);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> multiExponentiationArgumentService.getDiagonalProducts(ciphertexts, differentGroupExponents));
		assertEquals("The exponents group must have the order of the ciphertexts group.", exception.getMessage());
	}

	@Test
	@DisplayName("with specific values returns the expected result")
	void getDiagonalProductsWithSpecificValues() {
		// Create groups
		final BigInteger p = BigInteger.valueOf(23);
		final BigInteger q = BigInteger.valueOf(11);
		final BigInteger g = BigInteger.valueOf(2);

		final GqGroup gqGroup = new GqGroup(p, q, g);
		final ZqGroup zqGroup = new ZqGroup(q);

		// Create BigIntegers
		final BigInteger ZERO = BigInteger.ZERO;
		final BigInteger ONE = BigInteger.ONE;
		final BigInteger THREE = BigInteger.valueOf(3);
		final BigInteger FOUR = BigInteger.valueOf(4);
		final BigInteger FIVE = BigInteger.valueOf(5);
		final BigInteger SIX = BigInteger.valueOf(6);
		final BigInteger EIGHT = BigInteger.valueOf(8);
		final BigInteger NINE = BigInteger.valueOf(9);

		// Create GqElements
		final GqElement gOne = gqGroup.getIdentity();
		final GqElement gTwo = gqGroup.getGenerator();
		final GqElement gThree = GqElementFactory.fromValue(THREE, gqGroup);
		final GqElement gFour = GqElementFactory.fromValue(FOUR, gqGroup);
		final GqElement gSix = GqElementFactory.fromValue(SIX, gqGroup);
		final GqElement gEight = GqElementFactory.fromValue(EIGHT, gqGroup);
		final GqElement gNine = GqElementFactory.fromValue(NINE, gqGroup);
		final GqElement gTwelve = GqElementFactory.fromValue(BigInteger.valueOf(12), gqGroup);
		final GqElement gThirteen = GqElementFactory.fromValue(BigInteger.valueOf(13), gqGroup);
		final GqElement gSixteen = GqElementFactory.fromValue(BigInteger.valueOf(16), gqGroup);
		final GqElement gEighteen = GqElementFactory.fromValue(BigInteger.valueOf(18), gqGroup);

		// Create ZqElements
		final ZqElement zZero = ZqElement.create(ZERO, zqGroup);
		final ZqElement zOne = ZqElement.create(ONE, zqGroup);
		final ZqElement zThree = ZqElement.create(THREE, zqGroup);
		final ZqElement zFive = ZqElement.create(FIVE, zqGroup);
		final ZqElement zNine = ZqElement.create(NINE, zqGroup);

		// Create the ciphertext matrix:
		// C0 = [ {1, ( 3, 6,  4)} { 4, (12, 16, 6)} ]
		// C1 = [ {1, (13, 4, 18)} {13, ( 2,  3, 1)} ]
		final ElGamalMultiRecipientCiphertext c0 = ElGamalMultiRecipientCiphertext.create(gOne, Arrays.asList(gThree, gSix, gFour));
		final ElGamalMultiRecipientCiphertext c1 = ElGamalMultiRecipientCiphertext.create(gFour, Arrays.asList(gTwelve, gSixteen, gSix));
		final ElGamalMultiRecipientCiphertext c2 = ElGamalMultiRecipientCiphertext.create(gOne, Arrays.asList(gThirteen, gFour, gEighteen));
		final ElGamalMultiRecipientCiphertext c3 = ElGamalMultiRecipientCiphertext.create(gThirteen, Arrays.asList(gTwo, gThree, gOne));
		final GroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> ciphertextMatrix = GroupVector.of(c0, c1, c2, c3).toMatrix(2, 2);

		// Create the exponent matrix
		// A = [0 3 5]
		// 	   [1 9 1]
		final GroupMatrix<ZqElement, ZqGroup> matrixA = GroupVector.of(zZero, zThree, zFive, zOne, zNine, zOne).toMatrix(2, 3);

		// Create the expected output
		// D = ( {13, (2, 3, 1)}, {12, (13, 9, 9)}, {8, (13, 16, 13)}, {4, (18, 9, 3)} )
		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> expected = GroupVector.of(
				ElGamalMultiRecipientCiphertext.create(gThirteen, Arrays.asList(gTwo, gThree, gOne)),
				ElGamalMultiRecipientCiphertext.create(gTwelve, Arrays.asList(gThirteen, gNine, gNine)),
				ElGamalMultiRecipientCiphertext.create(gEight, Arrays.asList(gThirteen, gSixteen, gThirteen)),
				ElGamalMultiRecipientCiphertext.create(gFour, Arrays.asList(gEighteen, gNine, gThree))
		);

		final ElGamalGenerator elGamalGenerator = new ElGamalGenerator(gqGroup);
		final ElGamalMultiRecipientPublicKey publicKey = elGamalGenerator.genRandomPublicKey(3);

		// The commitment key and the hash service are only needed for instantiating the service
		// and are not relevant for the test itself
		final TestCommitmentKeyGenerator ckGenerator = new TestCommitmentKeyGenerator(gqGroup);
		final CommitmentKey commitmentKey = ckGenerator.genCommitmentKey(3);
		final HashService hashService = TestHashService.create(q);
		final MultiExponentiationArgumentService service = new MultiExponentiationArgumentService(publicKey, commitmentKey, new RandomService(),
				hashService);

		assertEquals(expected, service.getDiagonalProducts(ciphertextMatrix, matrixA));
	}
}
