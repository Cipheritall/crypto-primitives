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

import static ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext.getCiphertext;
import static ch.post.it.evoting.cryptoprimitives.mixnet.TestParser.parseCiphertexts;
import static ch.post.it.evoting.cryptoprimitives.mixnet.TestParser.parseCommitment;
import static ch.post.it.evoting.cryptoprimitives.mixnet.TestShuffleArgumentGenerator.ShuffleArgumentPair;
import static ch.post.it.evoting.cryptoprimitives.test.tools.GroupVectors.with;
import static java.util.stream.Collectors.collectingAndThen;
import static java.util.stream.Collectors.toList;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
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
import ch.post.it.evoting.cryptoprimitives.HashService;
import ch.post.it.evoting.cryptoprimitives.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientMessage;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
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
	private static MixnetHashService hashService;

	@BeforeAll
	static void setUpAll() {
		elGamalGenerator = new ElGamalGenerator(gqGroup);
		commitmentKeyGenerator = new TestCommitmentKeyGenerator(gqGroup);
		hashService = TestHashService.create(gqGroup.getQ());
	}

	@Nested
	@DisplayName("constructed with")
	class ConstructorTest {

		private int k;
		private ElGamalMultiRecipientPublicKey publicKey;
		private CommitmentKey commitmentKey;

		@BeforeEach
		void setUp() {
			k = secureRandom.nextInt(KEY_ELEMENTS_NUMBER - 2) + 2;

			publicKey = elGamalGenerator.genRandomPublicKey(k);
			commitmentKey = commitmentKeyGenerator.genCommitmentKey(k);
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
		@DisplayName("public and commitments keys from different group throws IllegalArgumentException")
		void constructPublicCommitmentKeysDiffGroup() {
			final ElGamalMultiRecipientPublicKey otherPublicKey = new ElGamalGenerator(otherGqGroup).genRandomPublicKey(k);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> new ShuffleArgumentService(otherPublicKey, commitmentKey, randomService, hashService));
			assertEquals("The public key and commitment key must belong to the same group.", exception.getMessage());
		}
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
					() -> shuffleArgumentService.getShuffleArgument(shuffleStatement, shuffleWitness, m, 0));
			assertEquals("The number of columns for the ciphertext matrices must be strictly positive.",
					columnsIllegalArgumentException.getMessage());
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
			final ShuffleWitness differentShuffleWitness = new ShuffleWitness(this.shuffleWitness.getPermutation(), differentRandomness);

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
					.mapToObj(i -> getCiphertext(ones, shuffleWitness.getRandomness().get(i), longerPublicKey)
							.multiply(longerCiphertexts.get(shuffleWitness.getPermutation().get(i))))
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
			final List<ElGamalMultiRecipientCiphertext> shuffledCiphertexts = new ArrayList<>(shuffleStatement.getShuffledCiphertexts());
			final ElGamalMultiRecipientCiphertext first = shuffledCiphertexts.get(0);
			final ElGamalMultiRecipientCiphertext otherFirst = Generators.genWhile(() -> elGamalGenerator.genRandomCiphertext(l), first::equals);
			shuffledCiphertexts.set(0, otherFirst);

			// Recreate shuffled ciphertexts and statement.
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> differentShuffledCiphertexts = GroupVector.from(
					shuffledCiphertexts);
			final ShuffleStatement differentShuffleStatement = new ShuffleStatement(this.shuffleStatement.getCiphertexts(),
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
			final MixnetHashService hashServiceMock = mock(MixnetHashService.class);
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
			assertTrue(shuffleArgumentService.verifyShuffleArgument(shuffleStatement, shuffleArgument, m, n));
		}

		@Test
		@DisplayName("invalid number of rows or columns throws IllegalArgumentException")
		void verifyShuffleArgumentInvalidRowsCols() {
			final IllegalArgumentException rowsIllegalArgumentException = assertThrows(IllegalArgumentException.class,
					() -> shuffleArgumentService.verifyShuffleArgument(shuffleStatement, shuffleArgument, 0, n));
			assertEquals("The number of rows for the ciphertext matrices must be strictly positive.", rowsIllegalArgumentException.getMessage());

			final IllegalArgumentException columnsIllegalArgumentException = assertThrows(IllegalArgumentException.class,
					() -> shuffleArgumentService.verifyShuffleArgument(shuffleStatement, shuffleArgument, m, 0));
			assertEquals("The number of columns for the ciphertext matrices must be strictly positive.",
					columnsIllegalArgumentException.getMessage());
		}

		@Test
		@DisplayName("m different from commitment vectors size throws IllegalArgumentException")
		void verifyShuffleArgumentMDiffSizeCommitments() {
			final int tooBigM = shuffleArgument.getcA().size() + 1;

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
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts = shuffleStatement.getCiphertexts();
			final int randomIndex = secureRandom.nextInt(ciphertexts.size());
			final ElGamalMultiRecipientCiphertext ciphertext = ciphertexts.get(randomIndex);
			final ElGamalMultiRecipientCiphertext otherCiphertext = elGamalGenerator.otherCiphertext(ciphertext);
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> badCiphertexts = with(ciphertexts, randomIndex, otherCiphertext);

			final ShuffleStatement badShuffleStatement = new ShuffleStatement(badCiphertexts, shuffleStatement.getShuffledCiphertexts());

			assertFalse(shuffleArgumentService.verifyShuffleArgument(badShuffleStatement, shuffleArgument, m, n));
		}

		@Test
		@DisplayName("incorrect shuffled ciphertexts C' throws IllegalArgumentException")
		void verifyShuffleArgumentIncorrectShuffledCPrime() {
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> shuffledCiphertexts = shuffleStatement.getShuffledCiphertexts();
			final int randomIndex = secureRandom.nextInt(shuffledCiphertexts.size());
			final ElGamalMultiRecipientCiphertext shuffledCiphertext = shuffledCiphertexts.get(randomIndex);
			final ElGamalMultiRecipientCiphertext otherCiphertext = elGamalGenerator.otherCiphertext(shuffledCiphertext);
			final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> badShuffledCiphertexts =
					with(shuffledCiphertexts, randomIndex, otherCiphertext);

			final ShuffleStatement badShuffleStatement = new ShuffleStatement(shuffleStatement.getShuffledCiphertexts(), badShuffledCiphertexts);

			assertFalse(shuffleArgumentService.verifyShuffleArgument(badShuffleStatement, shuffleArgument, m, n));
		}

		@Test
		@DisplayName("incorrect commitment vector c_A does not verify")
		void verifyShuffleArgumentIncorrectCA() {
			final GroupVector<GqElement, GqGroup> commitmentA = shuffleArgument.getcA();

			final GqElement badCA0 = commitmentA.get(0).multiply(gqGroup.getGenerator());
			final GroupVector<GqElement, GqGroup> badCommitmentA = with(commitmentA, 0, badCA0);
			final ShuffleArgument badShuffleArgument = new ShuffleArgument.Builder()
					.withCA(badCommitmentA)
					.withCB(shuffleArgument.getcB())
					.withProductArgument(shuffleArgument.getProductArgument())
					.withMultiExponentiationArgument(shuffleArgument.getMultiExponentiationArgument())
					.build();

			assertFalse(shuffleArgumentService.verifyShuffleArgument(shuffleStatement, badShuffleArgument, m, n));
		}

		@Test
		@DisplayName("incorrect commitment vector c_B does not verify")
		void verifyShuffleArgumentIncorrectCB() {
			final GroupVector<GqElement, GqGroup> commitmentB = shuffleArgument.getcB();

			final GqElement badCBm = commitmentB.get(0).multiply(gqGroup.getGenerator());
			final GroupVector<GqElement, GqGroup> badCommitmentB = with(commitmentB, 0, badCBm);
			final ShuffleArgument badShuffleArgument = new ShuffleArgument.Builder()
					.withCA(shuffleArgument.getcA())
					.withCB(badCommitmentB)
					.withProductArgument(shuffleArgument.getProductArgument())
					.withMultiExponentiationArgument(shuffleArgument.getMultiExponentiationArgument())
					.build();

			assertFalse(shuffleArgumentService.verifyShuffleArgument(shuffleStatement, badShuffleArgument, m, n));
		}

		@Test
		@DisplayName("incorrect product argument returns false")
		void verifyShuffleArgumentFailedProductVerif() {
			final ProductArgument productArgument = shuffleArgument.getProductArgument();

			final SingleValueProductArgument singleValueProductArgument = productArgument.getSingleValueProductArgument();
			final ZqElement badRTilde = zqGroupGenerator.otherElement(singleValueProductArgument.getRTilde());
			final SingleValueProductArgument badSingleValueProductArgument = new SingleValueProductArgument.Builder()
					.withCd(singleValueProductArgument.getCd())
					.withCLowerDelta(singleValueProductArgument.getCLowerDelta())
					.withCUpperDelta(singleValueProductArgument.getCUpperDelta())
					.withATilde(singleValueProductArgument.getATilde())
					.withBTilde(singleValueProductArgument.getBTilde())
					.withRTilde(badRTilde)
					.withSTilde(singleValueProductArgument.getSTilde())
					.build();

			ProductArgument badProductArgument;
			if (m == 1) {
				badProductArgument = new ProductArgument(badSingleValueProductArgument);
			} else {
				badProductArgument = new ProductArgument(productArgument.getCommitmentB(), productArgument.getHadamardArgument(),
						badSingleValueProductArgument);
			}

			final ShuffleArgument badShuffleArgument = new ShuffleArgument.Builder()
					.withCA(shuffleArgument.getcA())
					.withCB(shuffleArgument.getcB())
					.withProductArgument(badProductArgument)
					.withMultiExponentiationArgument(shuffleArgument.getMultiExponentiationArgument())
					.build();

			assertFalse(shuffleArgumentService.verifyShuffleArgument(shuffleStatement, badShuffleArgument, m, n));
		}

		@Test
		@DisplayName("incorrect multi-exponentiation argument returns false")
		void verifyShuffleArgumentFailedMultiExpVerif() {
			final MultiExponentiationArgument multiExponentiationArgument = shuffleArgument.getMultiExponentiationArgument();

			final GqElement badCA0 = multiExponentiationArgument.getcA0().multiply(gqGroup.getGenerator());
			final MultiExponentiationArgument badMultiExponentiationArgument = new MultiExponentiationArgument.Builder()
					.withcA0(badCA0)
					.withcBVector(multiExponentiationArgument.getcBVector())
					.withEVector(multiExponentiationArgument.getEVector())
					.withaVector(multiExponentiationArgument.getaVector())
					.withr(multiExponentiationArgument.getR())
					.withb(multiExponentiationArgument.getB())
					.withs(multiExponentiationArgument.getS())
					.withtau(multiExponentiationArgument.getTau())
					.build();

			final ShuffleArgument badShuffleArgument = new ShuffleArgument.Builder()
					.withCA(shuffleArgument.getcA())
					.withCB(shuffleArgument.getcB())
					.withProductArgument(shuffleArgument.getProductArgument())
					.withMultiExponentiationArgument(badMultiExponentiationArgument)
					.build();

			assertFalse(shuffleArgumentService.verifyShuffleArgument(shuffleStatement, badShuffleArgument, m, n));
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
						.withCA(cA)
						.withCB(cB)
						.withProductArgument(productArgument)
						.withMultiExponentiationArgument(multiExponentiationArgument)
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
				Boolean output, String description) throws NoSuchAlgorithmException {

			HashService hashService = new HashService(MessageDigest.getInstance("SHA-256"));
			MixnetHashService mixnetHashService = new MixnetHashService(hashService, pk.getGroup().getQ().bitLength());
			ShuffleArgumentService service = new ShuffleArgumentService(pk, ck, randomService, mixnetHashService);
			assertEquals(output, service.verifyShuffleArgument(statement, argument, m, n), String.format("assertion failed for: %s", description));
		}
	}
}
