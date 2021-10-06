/*
 * Copyright 2021 Post CH Ltd
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
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static ch.post.it.evoting.cryptoprimitives.GroupVector.toGroupVector;
import static ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext.getCiphertext;
import static ch.post.it.evoting.cryptoprimitives.mixnet.TestParser.parseCiphertexts;
import static ch.post.it.evoting.cryptoprimitives.mixnet.TestParser.parseCommitment;
import static ch.post.it.evoting.cryptoprimitives.mixnet.TestShuffleArgumentGenerator.ShuffleArgumentPair;
import static java.util.stream.Collectors.collectingAndThen;
import static java.util.stream.Collectors.toList;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.VerificationResult;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientMessage;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.hashing.TestHashService;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.GroupVectors;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.Generators;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.JsonData;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.TestParameters;

@DisplayName("A ShuffleArgumentService")
class ShuffleArgumentServiceTest extends TestGroupSetup {

	private static final int KEY_ELEMENTS_NUMBER = 11;
	private static final RandomService randomService = new RandomService();
	private static final SecureRandom secureRandom = new SecureRandom();
	private static final PermutationService permutationService = new PermutationService(randomService);

	private static ElGamalGenerator elGamalGenerator;
	private static TestCommitmentKeyGenerator commitmentKeyGenerator;
	private static HashService hashService;

	@BeforeAll
	static void setUpAll() {
		elGamalGenerator = new ElGamalGenerator(gqGroup);
		commitmentKeyGenerator = new TestCommitmentKeyGenerator(gqGroup);
		hashService = TestHashService.create(gqGroup.getQ());
	}

	@Nested
	@DisplayName("constructed with")
	class ConstructorTest {

		private ElGamalMultiRecipientPublicKey publicKey;
		private CommitmentKey commitmentKey;

		@BeforeEach
		void setUp() {
			int publicKeySize = secureRandom.nextInt(KEY_ELEMENTS_NUMBER - 2) + 2;
			publicKey = elGamalGenerator.genRandomPublicKey(publicKeySize);

			int commitmentKeySize = secureRandom.nextInt(KEY_ELEMENTS_NUMBER - 2) + 2;
			commitmentKey = commitmentKeyGenerator.genCommitmentKey(commitmentKeySize);
		}

		@Test
		@DisplayName("valid parameters does not throw")
		void construct() {
			assertDoesNotThrow(() -> new ShuffleArgumentService(publicKey, commitmentKey, randomService, hashService));
		}

		@Test
		@DisplayName("any null parameter throws NullPointerException")
		void constructNullParams() {
			assertAll(
					() -> assertThrows(NullPointerException.class, () -> new ShuffleArgumentService(null, commitmentKey, randomService, hashService)),
					() -> assertThrows(NullPointerException.class, () -> new ShuffleArgumentService(publicKey, null, randomService, hashService)),
					() -> assertThrows(NullPointerException.class, () -> new ShuffleArgumentService(publicKey, commitmentKey, null, hashService)),
					() -> assertThrows(NullPointerException.class, () -> new ShuffleArgumentService(publicKey, commitmentKey, randomService, null))
			);
		}

		@Test
		@DisplayName("a hashService that has a too long hash length throws an IllegalArgumentException")
		void constructWithHashServiceWithTooLongHashLength() {
			HashService otherHashService = HashService.getInstance();
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> new ShuffleArgumentService(publicKey, commitmentKey, randomService, otherHashService));
			assertEquals("The hash service's bit length must be smaller than the bit length of q.", exception.getMessage());
		}

		@Test
		@DisplayName("public and commitments keys from different group throws IllegalArgumentException")
		void constructPublicCommitmentKeysDiffGroup() {
			final ElGamalMultiRecipientPublicKey otherPublicKey = new ElGamalGenerator(otherGqGroup).genRandomPublicKey(publicKey.size());

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> new ShuffleArgumentService(otherPublicKey, commitmentKey, randomService, hashService));
			assertEquals("The public key and commitment key must belong to the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("commitment key with only 1 element throws IllegalArgumentException")
		void constructCommitmentKeyTooShort() {
			final CommitmentKey shortCommitmentKey = commitmentKeyGenerator.genCommitmentKey(1);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> new ShuffleArgumentService(publicKey, shortCommitmentKey, randomService, hashService));
			assertEquals("The commitment key must be at least of size 2.", exception.getMessage());
		}
	}

	private static class SpecificValues {
		int m = 2;
		int n = 2;

		// Create groups
		BigInteger p = BigInteger.valueOf(23);
		BigInteger q = BigInteger.valueOf(11);
		BigInteger g = BigInteger.valueOf(2);

		GqGroup gqGroup = new GqGroup(p, q, g);
		ZqGroup zqGroup = new ZqGroup(q);

		// Create BigIntegers
		private final BigInteger ZERO = BigInteger.ZERO;
		private final BigInteger ONE = BigInteger.ONE;
		private final BigInteger TWO = BigInteger.valueOf(2);
		private final BigInteger THREE = BigInteger.valueOf(3);
		private final BigInteger FOUR = BigInteger.valueOf(4);
		private final BigInteger FIVE = BigInteger.valueOf(5);
		private final BigInteger SIX = BigInteger.valueOf(6);
		private final BigInteger SEVEN = BigInteger.valueOf(7);
		private final BigInteger EIGHT = BigInteger.valueOf(8);
		private final BigInteger NINE = BigInteger.valueOf(9);
		private final BigInteger TEN = BigInteger.TEN;

		// Create GqElements
		GqElement gOne = gqGroup.getIdentity();
		GqElement gTwo = gqGroup.getGenerator();
		GqElement gThree = GqElement.create(THREE, gqGroup);
		GqElement gFour = GqElement.create(FOUR, gqGroup);
		GqElement gSix = GqElement.create(SIX, gqGroup);
		GqElement gEight = GqElement.create(EIGHT, gqGroup);
		GqElement gNine = GqElement.create(NINE, gqGroup);
		GqElement gTwelve = GqElement.create(BigInteger.valueOf(12), gqGroup);
		GqElement gThirteen = GqElement.create(BigInteger.valueOf(13), gqGroup);
		GqElement gSixteen = GqElement.create(BigInteger.valueOf(16), gqGroup);
		GqElement gEighteen = GqElement.create(BigInteger.valueOf(18), gqGroup);

		// Create ZqElements
		ZqElement zOne = ZqElement.create(ONE, zqGroup);
		ZqElement zTwo = ZqElement.create(TWO, zqGroup);
		ZqElement zThree = ZqElement.create(THREE, zqGroup);
		ZqElement zFour = ZqElement.create(FOUR, zqGroup);
		ZqElement zFive = ZqElement.create(FIVE, zqGroup);
		ZqElement zSix = ZqElement.create(SIX, zqGroup);
		ZqElement zSeven = ZqElement.create(SEVEN, zqGroup);
		ZqElement zEight = ZqElement.create(EIGHT, zqGroup);
		ZqElement zNine = ZqElement.create(NINE, zqGroup);
		ZqElement zTen = ZqElement.create(TEN, zqGroup);

		// Create the public key: pk = (8, 13, 4)
		ElGamalMultiRecipientPublicKey publicKey = new ElGamalMultiRecipientPublicKey(Arrays.asList(gEight, gThirteen, gFour));

		// Create the ciphertexts
		ElGamalMultiRecipientMessage m0 = new ElGamalMultiRecipientMessage(ImmutableList.of(gFour, gEight, gThree));
		ElGamalMultiRecipientMessage m1 = new ElGamalMultiRecipientMessage(ImmutableList.of(gSixteen, gTwo, gNine));
		ElGamalMultiRecipientMessage m2 = new ElGamalMultiRecipientMessage(ImmutableList.of(gThree, gSix, gFour));
		ElGamalMultiRecipientMessage m3 = new ElGamalMultiRecipientMessage(ImmutableList.of(gThirteen, gFour, gEighteen));

		ElGamalMultiRecipientCiphertext c0 = ElGamalMultiRecipientCiphertext.getCiphertext(m0, zFive, publicKey);
		ElGamalMultiRecipientCiphertext c1 = ElGamalMultiRecipientCiphertext.getCiphertext(m1, zTen, publicKey);
		ElGamalMultiRecipientCiphertext c2 = ElGamalMultiRecipientCiphertext.getCiphertext(m2, zSeven, publicKey);
		ElGamalMultiRecipientCiphertext c3 = ElGamalMultiRecipientCiphertext.getCiphertext(m3, zTwo, publicKey);
		// Create the vector of ciphertexts:
		// C = ({9, (18, 9, 13)}, {12, (2, 9, 8)}, {13, (13, 8, 9)}, {4, (4, 9, 12)})
		GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> c = GroupVector.of(c0, c1, c2, c3);

		// Create the permutation: pi = [1, 3, 2, 0]
		Permutation permutation = new Permutation(ImmutableList.of(1, 3, 2, 0));
		// Create the randomness: rho = (3, 9, 4, 2)
		GroupVector<ZqElement, ZqGroup> rho = GroupVector.of(zThree, zNine, zFour, zTwo);

		ElGamalMultiRecipientMessage ones = ElGamalMultiRecipientMessage.ones(gqGroup, 3);
		// Create the vector of shuffled ciphertexts:
		// C' = ({4, (12, 16, 6)}, {1, (13, 4, 18)}, {1, (3, 6, 4)}, {13, (2, 3, 1)})
		GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> cPrime = IntStream.range(0, 4)
				.mapToObj(i -> ElGamalMultiRecipientCiphertext.getCiphertext(ones, rho.get(i), publicKey).multiply(c.get(permutation.get(i))))
				.collect(toGroupVector());

		// Create the ShuffleArgumentService
		// Create the commitment key: ck = {3, (6, 13, 12)}
		CommitmentKey commitmentKey = new CommitmentKey(gThree, ImmutableList.of(gSix, gThirteen, gTwelve));
		// Shuffle: r = (9, 2), s = (10, 8)
		// Product: s = 10
		// Zero: a0 = (2, 5), bm = (1, 4), r0 = 7, sm = 3, t = (6, 2, 4, 5, 8)
		// Single: d = (4, 9), rd = 0, s0 = 1, sx = 7
		// Multi: a0 = (0, 1), r0 = 6, b = (2, 3, 7, 9), s = (10, 1, 3, 4), tau = (5, 6, 8, 7)
		List<BigInteger> randomValues = Arrays.asList(NINE, TWO, TEN, EIGHT,
				TEN,
				TWO, FIVE, ONE, FOUR, SEVEN, THREE, SIX, TWO, FOUR, FIVE, EIGHT,
				FOUR, NINE, ZERO, ONE, SEVEN,
				ZERO, ONE, SIX, TWO, THREE, SEVEN, NINE, TEN, ONE, THREE, FOUR, FIVE, SIX, EIGHT, SEVEN);
		RandomService randomService = new RandomService() {
			final Iterator<BigInteger> values = randomValues.iterator();

			@Override
			public BigInteger genRandomInteger(BigInteger upperBound) {
				return values.next();
			}
		};
		HashService shuffleHashService = TestHashService.create(gqGroup.getQ());
		ShuffleArgumentService shuffleArgumentService = new ShuffleArgumentService(publicKey, commitmentKey, randomService, shuffleHashService);

		// Create the statement and the witness
		ShuffleStatement statement = new ShuffleStatement(c, cPrime);
		ShuffleWitness witness = new ShuffleWitness(permutation, rho);

		// Create the expected ZeroArgument
		ZeroArgument zeroArgument = new ZeroArgument.Builder()
				.with_c_A_0(gTwelve)
				.with_c_B_m(gEighteen)
				.with_c_d(GroupVector.of(gSixteen, gNine, gTwelve, gOne, gSix))
				.with_a_prime(GroupVector.of(zEight, zFive))
				.with_b_prime(GroupVector.of(zTen, zTwo))
				.with_r_prime(zOne)
				.with_s_prime(zEight)
				.with_t_prime(zTwo)
				.build();

		// Create the expected HadamardArgument
		GroupVector<GqElement, GqGroup> cBhadamard = GroupVector.of(gThirteen, gFour);
		HadamardArgument hadamardArgument = new HadamardArgument(cBhadamard, zeroArgument);

		// Create the expected SingleValueProductArgument
		SingleValueProductArgument singleValueProductArgument = new SingleValueProductArgument.Builder()
				.with_c_d(gOne)
				.with_c_delta(gEight)
				.with_c_Delta(gSixteen)
				.with_a_tilde(GroupVector.of(zEight, zTen))
				.with_b_tilde(GroupVector.of(zEight, zFour))
				.with_r_tilde(zTen)
				.with_s_tilde(zEight)
				.build();

		// Create the expected ProductArgument:
		// cb = 9
		// Hadamard: cB = (16, 9), Zero: cA0 = 12, cBm = 18, cd = (18, 4, 13, 1, 4), a' = (8, 8), b' = (6, 3), r' = 7, s' = 0, t' = 5
		// Single: cd = 1, cδ = 8, cΔ = 1, aTilde = (8, 5), bTilde = (8, 7), rTilde = 7, sTilde = 7
		ProductArgument productArgument = new ProductArgument(gFour, hadamardArgument, singleValueProductArgument);

		GroupVector<GqElement, GqGroup> cBmulti = GroupVector.of(gTwelve, gFour, gOne, gEight);
		GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> eVector = GroupVector.of(
				ElGamalMultiRecipientCiphertext.create(gTwo, Arrays.asList(gThirteen, gTwo, gTwo)),
				ElGamalMultiRecipientCiphertext.create(gEight, Arrays.asList(gEight, gTwo, gThirteen)),
				ElGamalMultiRecipientCiphertext.create(gTwelve, Arrays.asList(gThree, gThree, gFour)),
				ElGamalMultiRecipientCiphertext.create(gEighteen, Arrays.asList(gTwelve, gEight, gThree))
		);

		// Create the expected MultiExponentiationArgument:
		// cA0 = 1, cB = (12, 4, 1, 8), E = ({2, (13, 2, 2)}, {9, (18, 18, 6)}, {9, (4, 13, 1)}, {6, (8, 3, 6)})
		// a = (2, 4), r = 7, b = 1, s = 5, tau = 5
		MultiExponentiationArgument multiExponentiationArgument = new MultiExponentiationArgument.Builder()
				.with_c_A_0(gOne)
				.with_c_B(cBmulti)
				.with_E(eVector)
				.with_a(GroupVector.of(zEight, zNine))
				.with_r(zNine)
				.with_b(zSeven)
				.with_s(zSix)
				.with_tau(zOne)
				.build();

		// Create the expected output:
		// cA = (8, 2), cB = (8, 18)
		GroupVector<GqElement, GqGroup> cAshuffle = GroupVector.of(gEight, gTwo);
		GroupVector<GqElement, GqGroup> cBshuffle = GroupVector.of(gEight, gEighteen);

		ShuffleArgument argument = new ShuffleArgument.Builder()
				.with_c_A(cAshuffle)
				.with_c_B(cBshuffle)
				.with_productArgument(productArgument)
				.with_multiExponentiationArgument(multiExponentiationArgument)
				.build();
	}

	@Nested
	@DisplayName("calling getShuffleArgument with")
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	class GetShuffleArgumentTest {

		private ElGamalMultiRecipientPublicKey publicKey;
		private ShuffleArgumentService shuffleArgumentService;

		private ShuffleStatement shuffleStatement;
		private ShuffleWitness shuffleWitness;
		private int m;
		private int n;
		private int N;
		private int l;

		@BeforeAll
		void setUpAll() {
			publicKey = elGamalGenerator.genRandomPublicKey(KEY_ELEMENTS_NUMBER);

			final CommitmentKey commitmentKey = commitmentKeyGenerator.genCommitmentKey(KEY_ELEMENTS_NUMBER);

			shuffleArgumentService = new ShuffleArgumentService(publicKey, commitmentKey, randomService, hashService);
		}

		@BeforeEach
		void setUp() {
			// getShuffleArgument needs a permutation vector constructed with a permutation having values in [0, N]. Because test groups are small,
			// we need to ensure N < q. The loop stays fast because of small test groups and bounds.
			do {
				m = secureRandom.nextInt(KEY_ELEMENTS_NUMBER - 1) + 1;
				n = secureRandom.nextInt(KEY_ELEMENTS_NUMBER - 2) + 2;
			} while (BigInteger.valueOf((long) m * n).compareTo(zqGroup.getQ()) >= 0);
			N = m * n;

			// Create a witness.
			final Permutation permutation = permutationService.genPermutation(N);
			final GroupVector<ZqElement, ZqGroup> randomness = zqGroupGenerator.genRandomZqElementVector(N);

			shuffleWitness = new ShuffleWitness(permutation, randomness);

			// Create the corresponding statement.
			l = secureRandom.nextInt(KEY_ELEMENTS_NUMBER - 1) + 1;
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts = elGamalGenerator.genRandomCiphertextVector(N, l);

			final ElGamalMultiRecipientMessage ones = ElGamalMultiRecipientMessage.ones(gqGroup, l);
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> shuffledCiphertexts = IntStream.range(0, N)
					.mapToObj(i -> getCiphertext(ones, randomness.get(i), publicKey)
							.multiply(ciphertexts.get(permutation.get(i))))
					.collect(collectingAndThen(toList(), GroupVector::from));

			shuffleStatement = new ShuffleStatement(ciphertexts, shuffledCiphertexts);
		}

		@Test
		@DisplayName("valid parameters does not throw")
		void getShuffleArgumentTest() {
			assertDoesNotThrow(() -> shuffleArgumentService.getShuffleArgument(shuffleStatement, shuffleWitness, m, n));
		}

		@Test
		@DisplayName("any null parameter throws NullPointerException")
		void getShuffleArgumentNullParams() {
			assertThrows(NullPointerException.class, () -> shuffleArgumentService.getShuffleArgument(null, shuffleWitness, m, n));
			assertThrows(NullPointerException.class, () -> shuffleArgumentService.getShuffleArgument(shuffleStatement, null, m, n));
		}

		@Test
		@DisplayName("invalid number of rows or columns throws IllegalArgumentException")
		void getShuffleArgumentInvalidRowsCols() {
			final IllegalArgumentException rowsIllegalArgumentException = assertThrows(IllegalArgumentException.class,
					() -> shuffleArgumentService.getShuffleArgument(shuffleStatement, shuffleWitness, 0, n));
			assertEquals("The number of rows for the ciphertext matrices must be strictly positive.", rowsIllegalArgumentException.getMessage());

			final IllegalArgumentException columnsIllegalArgumentException = assertThrows(IllegalArgumentException.class,
					() -> shuffleArgumentService.getShuffleArgument(shuffleStatement, shuffleWitness, m, 1));
			assertEquals("The number of columns for the ciphertext matrices must be greater than or equal to 2.",
					columnsIllegalArgumentException.getMessage());
		}

		@Test
		@DisplayName("ciphertext matrix column count bigger than commitment key size throws IllegalArgumentException")
		void getShuffleArgumentTooShortCommitmentKey() {
			final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
					() -> shuffleArgumentService.getShuffleArgument(shuffleStatement, shuffleWitness, 1, KEY_ELEMENTS_NUMBER + 1));
			assertEquals("The number of columns for the ciphertext matrices must be smaller than or equal to the commitment key size.",
					illegalArgumentException.getMessage());
		}

		@Test
		@DisplayName("ciphertexts and permutation of different size throws IllegalArgumentException")
		void getShuffleArgumentCiphertextsPermutationDiffSize() {
			final Permutation longerPermutation = permutationService.genPermutation(N + 1);
			final GroupVector<ZqElement, ZqGroup> longerRandomness = zqGroupGenerator.genRandomZqElementVector(N + 1);
			final ShuffleWitness longerShuffleWitness = new ShuffleWitness(longerPermutation, longerRandomness);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> shuffleArgumentService.getShuffleArgument(shuffleStatement, longerShuffleWitness, m, n));
			assertEquals("The statement ciphertexts must have the same size as the permutation.", exception.getMessage());
		}

		@Test
		@DisplayName("ciphertexts and randomness having a different group order throws IllegalArgumentException")
		void getShuffleArgumentCiphertextsRandomnessDiffOrder() {
			final GroupVector<ZqElement, ZqGroup> differentRandomness = otherZqGroupGenerator.genRandomZqElementVector(N);
			final ShuffleWitness differentShuffleWitness = new ShuffleWitness(this.shuffleWitness.get_pi(), differentRandomness);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> shuffleArgumentService.getShuffleArgument(shuffleStatement, differentShuffleWitness, m, n));
			assertEquals("The randomness group must have the order of the ciphertexts group.", exception.getMessage());
		}

		@Test
		@DisplayName("ciphertexts longer than public key throws IllegalArgumentException")
		void getShuffleArgumentCiphertextsLongerThanPublicKey() {
			final int biggerL = KEY_ELEMENTS_NUMBER + 1;
			final ElGamalMultiRecipientPublicKey longerPublicKey = elGamalGenerator.genRandomPublicKey(biggerL);
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> longerCiphertexts = elGamalGenerator
					.genRandomCiphertextVector(N, biggerL);

			final ElGamalMultiRecipientMessage ones = ElGamalMultiRecipientMessage.ones(gqGroup, biggerL);
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> shuffledCiphertexts = IntStream.range(0, N)
					.mapToObj(i -> getCiphertext(ones, shuffleWitness.get_rho().get(i), longerPublicKey)
							.multiply(longerCiphertexts.get(shuffleWitness.get_pi().get(i))))
					.collect(collectingAndThen(toList(), GroupVector::from));

			final ShuffleStatement longerCiphertextsStatement = new ShuffleStatement(longerCiphertexts, shuffledCiphertexts);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> shuffleArgumentService.getShuffleArgument(longerCiphertextsStatement, shuffleWitness, m, n));
			assertEquals("The ciphertexts must be smaller than the public key.", exception.getMessage());
		}

		@Test
		@DisplayName("re-encrypted and shuffled ciphertexts C different C' throws IllegalArgumentException")
		void getShuffleArgumentCiphertextsShuffledCiphertextsDiff() {
			// Modify the shuffled ciphertexts by replacing its first element by a different ciphertext.
			final List<ElGamalMultiRecipientCiphertext> shuffledCiphertexts = new ArrayList<>(shuffleStatement.get_C_prime());
			final ElGamalMultiRecipientCiphertext first = shuffledCiphertexts.get(0);
			final ElGamalMultiRecipientCiphertext otherFirst = Generators.genWhile(() -> elGamalGenerator.genRandomCiphertext(l), first::equals);
			shuffledCiphertexts.set(0, otherFirst);

			// Recreate shuffled ciphertexts and statement.
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> differentShuffledCiphertexts = GroupVector.from(
					shuffledCiphertexts);
			final ShuffleStatement differentShuffleStatement = new ShuffleStatement(this.shuffleStatement.get_C(),
					differentShuffledCiphertexts);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> shuffleArgumentService.getShuffleArgument(differentShuffleStatement, shuffleWitness, m, n));
			assertEquals(
					"The shuffled ciphertexts provided in the statement do not correspond to the re-encryption and shuffle of C under pi and rho.",
					exception.getMessage());
		}

		@Test
		@DisplayName("ciphertexts vectors not decomposable into matrices throws IllegalArgumentException")
		void getShuffleArgumentNotDecomposableCiphertexts() {
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> shuffleArgumentService.getShuffleArgument(shuffleStatement, shuffleWitness, m + 1, n));
			assertEquals(String.format("The ciphertexts vectors must be decomposable into m * n matrices: %d != %d * %d.", N, m + 1, n),
					exception.getMessage());
		}


		@Test
		@DisplayName("specific values returns the expected result")
		void getShuffleArgumentWithSpecificValues() {
			SpecificValues specificValues = new SpecificValues();
			ShuffleArgument expected = specificValues.argument;
			ShuffleArgument actual = specificValues.shuffleArgumentService
					.getShuffleArgument(specificValues.statement, specificValues.witness, specificValues.m, specificValues.n);
			assertEquals(expected, actual);
		}
	}

	@Nested
	@DisplayName("calling verifyShuffleArgument with")
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	class VerifyShuffleArgumentTest {

		private ElGamalGenerator elGamalGenerator;
		private ElGamalMultiRecipientPublicKey publicKey;
		private ShuffleArgumentService shuffleArgumentService;

		private ShuffleStatement shuffleStatement;
		private ShuffleArgument shuffleArgument;
		private int m;
		private int n;
		private int N;
		private int l;

		@BeforeAll
		void setUpAll() {
			elGamalGenerator = new ElGamalGenerator(gqGroup);
			final TestCommitmentKeyGenerator commitmentKeyGenerator = new TestCommitmentKeyGenerator(gqGroup);

			publicKey = elGamalGenerator.genRandomPublicKey(KEY_ELEMENTS_NUMBER);
			final CommitmentKey commitmentKey = commitmentKeyGenerator.genCommitmentKey(KEY_ELEMENTS_NUMBER);

			// Necessary to return a constant value, otherwise some assertFalse tests can return true because of changes compensating each other (due
			// to small test groups).
			HashService hashServiceMock = mock(HashService.class);
			when(hashServiceMock.recursiveHash(any())).thenReturn(new byte[] { 0b10 });

			shuffleArgumentService = new ShuffleArgumentService(publicKey, commitmentKey, randomService, hashServiceMock);
		}

		@BeforeEach
		void setUp() {
			// getShuffleArgument needs a permutation vector constructed with a permutation having values in [0, N]. Because test groups are small,
			// we need to ensure N < q. The loop stays fast because of small test groups and bounds.
			do {
				m = secureRandom.nextInt(KEY_ELEMENTS_NUMBER - 1) + 1;
				n = secureRandom.nextInt(KEY_ELEMENTS_NUMBER - 2) + 2;
			} while (BigInteger.valueOf((long) m * n).compareTo(zqGroup.getQ()) >= 0);
			N = m * n;
			l = secureRandom.nextInt(KEY_ELEMENTS_NUMBER - 1) + 1;

			final TestShuffleArgumentGenerator shuffleArgumentGenerator = new TestShuffleArgumentGenerator(gqGroup);
			final ShuffleArgumentPair shuffleArgumentPair = shuffleArgumentGenerator.genShuffleArgumentPair(N, l, publicKey);
			shuffleStatement = shuffleArgumentPair.getStatement();
			final ShuffleWitness shuffleWitness = shuffleArgumentPair.getWitness();

			shuffleArgument = shuffleArgumentService.getShuffleArgument(shuffleStatement, shuffleWitness, m, n);
		}

		@Test
		@DisplayName("any null parameter throws NullPointerException")
		void verifyShuffleArgumentNullParams() {
			assertThrows(NullPointerException.class, () -> shuffleArgumentService.verifyShuffleArgument(null, shuffleArgument, m, n));
			assertThrows(NullPointerException.class, () -> shuffleArgumentService.verifyShuffleArgument(shuffleStatement, null, m, n));
		}

		@Test
		@DisplayName("valid parameters returns true")
		void verifyShuffleArgumentValidParams() {
			assertTrue(shuffleArgumentService.verifyShuffleArgument(shuffleStatement, shuffleArgument, m, n).isVerified());
		}

		@Test
		@DisplayName("invalid number of rows or columns throws IllegalArgumentException")
		void verifyShuffleArgumentInvalidRowsCols() {
			final IllegalArgumentException rowsIllegalArgumentException = assertThrows(IllegalArgumentException.class,
					() -> shuffleArgumentService.verifyShuffleArgument(shuffleStatement, shuffleArgument, 0, n));
			assertEquals("The number of rows for the ciphertext matrices must be strictly positive.", rowsIllegalArgumentException.getMessage());

			final IllegalArgumentException columnsIllegalArgumentException = assertThrows(IllegalArgumentException.class,
					() -> shuffleArgumentService.verifyShuffleArgument(shuffleStatement, shuffleArgument, m, 1));
			assertEquals("The number of columns for the ciphertext matrices must be greater than or equal to 2.",
					columnsIllegalArgumentException.getMessage());
		}

		@Test
		@DisplayName("ciphertext matrix column count bigger than commitment key size throws IllegalArgumentException")
		void verifyShuffleArgumentTooShortCommitmentKey() {
			final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
					() -> shuffleArgumentService.verifyShuffleArgument(shuffleStatement, shuffleArgument, 1, KEY_ELEMENTS_NUMBER + 1));
			assertEquals("The number of columns for the ciphertext matrices must be smaller than or equal to the commitment key size.",
					illegalArgumentException.getMessage());
		}

		@Test
		@DisplayName("m different from commitment vectors size throws IllegalArgumentException")
		void verifyShuffleArgumentMDiffSizeCommitments() {
			final int tooBigM = shuffleArgument.get_c_A().size() + 1;

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> shuffleArgumentService.verifyShuffleArgument(shuffleStatement, shuffleArgument, tooBigM, n));
			assertEquals("The m dimension of the argument must be equal to the input parameter m.", exception.getMessage());
		}

		@Test
		@DisplayName("m * n different from ciphertexts size throws IllegalArgumentException")
		void verifyShuffleArgumentMTimesNDiffCiphertextsSize() {
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> shuffleArgumentService.verifyShuffleArgument(shuffleStatement, shuffleArgument, m, n + 1));
			assertEquals("The product m * n must be equal to the statement's ciphertexts' size.", exception.getMessage());
		}

		@Test
		@DisplayName("statement and argument having incompatible groups throws IllegalArgumentException")
		void verifyShuffleArgumentDiffGroup() {
			final TestShuffleArgumentGenerator shuffleArgumentGenerator = new TestShuffleArgumentGenerator(otherGqGroup);
			final ShuffleStatement otherShuffleStatement = shuffleArgumentGenerator.genShuffleStatement(N, l);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> shuffleArgumentService.verifyShuffleArgument(otherShuffleStatement, shuffleArgument, m, n));
			assertEquals("The statement and the argument must have compatible groups.", exception.getMessage());
		}

		@Test
		@DisplayName("incorrect ciphertexts C throws IllegalArgumentException")
		void verifyShuffleArgumentIncorrectC() {
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts = shuffleStatement.get_C();
			final int randomIndex = secureRandom.nextInt(ciphertexts.size());
			final ElGamalMultiRecipientCiphertext ciphertext = ciphertexts.get(randomIndex);
			final ElGamalMultiRecipientCiphertext otherCiphertext = elGamalGenerator.otherCiphertext(ciphertext);
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> badCiphertexts = GroupVectors.set(ciphertexts, randomIndex, otherCiphertext);

			final ShuffleStatement badShuffleStatement = new ShuffleStatement(badCiphertexts, shuffleStatement.get_C_prime());

			final VerificationResult verificationResult = shuffleArgumentService.verifyShuffleArgument(badShuffleStatement, shuffleArgument, m, n);
			assertFalse(verificationResult.isVerified());
			assertEquals("Failed to verify MultiExponentiation Argument.", verificationResult.getErrorMessages().element());
		}

		@Test
		@DisplayName("incorrect shuffled ciphertexts C' throws IllegalArgumentException")
		void verifyShuffleArgumentIncorrectShuffledCPrime() {
			SpecificValues specificValues = new SpecificValues();
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> shuffledCiphertexts = specificValues.statement.get_C_prime();
			final int ciphertextToChangeIdx = 1;
			final ElGamalMultiRecipientCiphertext shuffledCiphertext = shuffledCiphertexts.get(ciphertextToChangeIdx);
			GroupVector<GqElement, GqGroup> phis = shuffledCiphertext.getPhi();
			int ciphertextElementToChangeIdx = 1;
			GroupVector<GqElement, GqGroup> differentPhis = GroupVectors.set(phis, ciphertextElementToChangeIdx, specificValues.gThirteen); //Was 4 originally
			final ElGamalMultiRecipientCiphertext differentCiphertext = ElGamalMultiRecipientCiphertext.create(shuffledCiphertext.getGamma(), differentPhis);
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> differentShuffleCiphertexts =
					GroupVectors.set(shuffledCiphertexts, ciphertextToChangeIdx, differentCiphertext);

			ShuffleStatement invalidStatement = new ShuffleStatement(specificValues.c, differentShuffleCiphertexts);

			final VerificationResult verificationResult = specificValues.shuffleArgumentService
					.verifyShuffleArgument(invalidStatement, specificValues.argument, specificValues.m, specificValues.n);
			assertFalse(verificationResult.isVerified());
		}

		@Test
		@DisplayName("incorrect commitment vector c_A does not verify")
		void verifyShuffleArgumentIncorrectCA() {
			final GroupVector<GqElement, GqGroup> commitmentA = shuffleArgument.get_c_A();

			final GqElement badCA0 = commitmentA.get(0).multiply(gqGroup.getGenerator());
			final GroupVector<GqElement, GqGroup> badCommitmentA = GroupVectors.set(commitmentA, 0, badCA0);
			final ShuffleArgument badShuffleArgument = new ShuffleArgument.Builder()
					.with_c_A(badCommitmentA)
					.with_c_B(shuffleArgument.get_c_B())
					.with_productArgument(shuffleArgument.getProductArgument())
					.with_multiExponentiationArgument(shuffleArgument.getMultiExponentiationArgument())
					.build();

			final VerificationResult verificationResult = shuffleArgumentService.verifyShuffleArgument(shuffleStatement, badShuffleArgument, m, n);
			assertFalse(verificationResult.isVerified());
			assertEquals("Failed to verify Product Argument.", verificationResult.getErrorMessages().getFirst());
		}

		@Test
		@DisplayName("incorrect commitment vector c_B does not verify")
		void verifyShuffleArgumentIncorrectCB() {
			final GroupVector<GqElement, GqGroup> commitmentB = shuffleArgument.get_c_B();

			final GqElement badCBm = commitmentB.get(0).multiply(gqGroup.getGenerator());
			final GroupVector<GqElement, GqGroup> badCommitmentB = GroupVectors.set(commitmentB, 0, badCBm);
			final ShuffleArgument badShuffleArgument = new ShuffleArgument.Builder()
					.with_c_A(shuffleArgument.get_c_A())
					.with_c_B(badCommitmentB)
					.with_productArgument(shuffleArgument.getProductArgument())
					.with_multiExponentiationArgument(shuffleArgument.getMultiExponentiationArgument())
					.build();

			final VerificationResult verificationResult = shuffleArgumentService.verifyShuffleArgument(shuffleStatement, badShuffleArgument, m, n);
			assertFalse(verificationResult.isVerified());
			assertEquals("Failed to verify Product Argument.", verificationResult.getErrorMessages().getFirst());
		}

		@Test
		@DisplayName("incorrect product argument returns false")
		void verifyShuffleArgumentFailedProductVerif() {
			final ProductArgument productArgument = shuffleArgument.getProductArgument();

			final SingleValueProductArgument singleValueProductArgument = productArgument.getSingleValueProductArgument();
			final ZqElement badRTilde = zqGroupGenerator.otherElement(singleValueProductArgument.get_r_tilde());
			final SingleValueProductArgument badSingleValueProductArgument = new SingleValueProductArgument.Builder()
					.with_c_d(singleValueProductArgument.get_c_d())
					.with_c_delta(singleValueProductArgument.get_c_delta())
					.with_c_Delta(singleValueProductArgument.get_c_Delta())
					.with_a_tilde(singleValueProductArgument.get_a_tilde())
					.with_b_tilde(singleValueProductArgument.get_b_tilde())
					.with_r_tilde(badRTilde)
					.with_s_tilde(singleValueProductArgument.get_s_tilde())
					.build();

			ProductArgument badProductArgument;
			if (productArgument.get_c_b().isPresent() && productArgument.getHadamardArgument().isPresent()) {
				badProductArgument = new ProductArgument(productArgument.get_c_b().get(), productArgument.getHadamardArgument().get(),
						badSingleValueProductArgument);
			} else {
				badProductArgument = new ProductArgument(badSingleValueProductArgument);
			}

			final ShuffleArgument badShuffleArgument = new ShuffleArgument.Builder()
					.with_c_A(shuffleArgument.get_c_A())
					.with_c_B(shuffleArgument.get_c_B())
					.with_productArgument(badProductArgument)
					.with_multiExponentiationArgument(shuffleArgument.getMultiExponentiationArgument())
					.build();

			final VerificationResult verificationResult = shuffleArgumentService.verifyShuffleArgument(shuffleStatement, badShuffleArgument, m, n);
			assertFalse(verificationResult.isVerified());
			assertEquals("Failed to verify Product Argument.", verificationResult.getErrorMessages().element());
		}

		@Test
		@DisplayName("incorrect multi-exponentiation argument returns false")
		void verifyShuffleArgumentFailedMultiExpVerif() {
			final MultiExponentiationArgument multiExponentiationArgument = shuffleArgument.getMultiExponentiationArgument();

			final GqElement badCA0 = multiExponentiationArgument.getc_A_0().multiply(gqGroup.getGenerator());
			final MultiExponentiationArgument badMultiExponentiationArgument = new MultiExponentiationArgument.Builder()
					.with_c_A_0(badCA0)
					.with_c_B(multiExponentiationArgument.get_c_B())
					.with_E(multiExponentiationArgument.get_E())
					.with_a(multiExponentiationArgument.get_a())
					.with_r(multiExponentiationArgument.get_r())
					.with_b(multiExponentiationArgument.get_b())
					.with_s(multiExponentiationArgument.get_s())
					.with_tau(multiExponentiationArgument.get_tau())
					.build();

			final ShuffleArgument badShuffleArgument = new ShuffleArgument.Builder()
					.with_c_A(shuffleArgument.get_c_A())
					.with_c_B(shuffleArgument.get_c_B())
					.with_productArgument(shuffleArgument.getProductArgument())
					.with_multiExponentiationArgument(badMultiExponentiationArgument)
					.build();

			final VerificationResult verificationResult = shuffleArgumentService.verifyShuffleArgument(shuffleStatement, badShuffleArgument, m, n);
			assertFalse(verificationResult.isVerified());
			assertEquals("Failed to verify MultiExponentiation Argument.", verificationResult.getErrorMessages().getFirst());
		}

		Stream<Arguments> jsonData() {
			final List<TestParameters> parametersList = TestParameters.fromResource("/mixnet/verify-shuffle-argument.json");

			return parametersList.stream().parallel().map(testParameters -> {
				// Context.
				final JsonData contextData = testParameters.getContext();
				final TestContextParser context = new TestContextParser(contextData);
				final GqGroup gqGroup = context.getGqGroup();

				final ElGamalMultiRecipientPublicKey publicKey = context.parsePublicKey();
				final CommitmentKey commitmentKey = context.parseCommitmentKey();

				// Input
				//Statement
				final JsonData statementData = testParameters.getInput().getJsonData("statement");
				final JsonData ciphertextsData = statementData.getJsonData("ciphertexts");
				GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts = parseCiphertexts(ciphertextsData, gqGroup);
				final JsonData shuffledCiphertextsData = statementData.getJsonData("shuffled_ciphertexts");
				GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> shuffledCiphertexts = parseCiphertexts(shuffledCiphertextsData, gqGroup);
				ShuffleStatement statement = new ShuffleStatement(ciphertexts, shuffledCiphertexts);

				//Argument
				final JsonData argumentData = testParameters.getInput().getJsonData("argument");
				GroupVector<GqElement, GqGroup> cA = parseCommitment(argumentData, "ca", gqGroup);
				GroupVector<GqElement, GqGroup> cB = parseCommitment(argumentData, "cb", gqGroup);

				TestArgumentParser argumentParser = new TestArgumentParser(gqGroup);
				JsonData productArgumentData = argumentData.getJsonData("product_argument");
				ProductArgument productArgument = argumentParser.parseProductArgument(productArgumentData);
				JsonData multiExpArgumentData = argumentData.getJsonData("multi_exp_argument");
				MultiExponentiationArgument multiExponentiationArgument = argumentParser.parseMultiExponentiationArgument(multiExpArgumentData);

				ShuffleArgument argument = new ShuffleArgument.Builder()
						.with_c_A(cA)
						.with_c_B(cB)
						.with_productArgument(productArgument)
						.with_multiExponentiationArgument(multiExponentiationArgument)
						.build();

				//m and n
				Integer m = testParameters.getInput().get("m", Integer.class);
				Integer n = testParameters.getInput().get("n", Integer.class);

				//Output
				final JsonData outputData = testParameters.getOutput();
				boolean output = outputData.get("result", Boolean.class);

				return Arguments.of(publicKey, commitmentKey, statement, argument, m, n, output, testParameters.getDescription());
			});
		}

		@ParameterizedTest(name = "{7}")
		@MethodSource("jsonData")
		@DisplayName("with real values gives expected result")
		void testRealData(ElGamalMultiRecipientPublicKey pk, CommitmentKey ck, ShuffleStatement statement, ShuffleArgument argument, int m, int n,
				Boolean output, String description) {

			HashService hashService = HashService.getInstance();
			ShuffleArgumentService service = new ShuffleArgumentService(pk, ck, randomService, hashService);
			assertEquals(output, service.verifyShuffleArgument(statement, argument, m, n).isVerified(),
					String.format("assertion failed for: %s", description));
		}
	}
}
