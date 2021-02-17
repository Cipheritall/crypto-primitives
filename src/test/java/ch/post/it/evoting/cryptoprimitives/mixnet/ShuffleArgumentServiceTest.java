/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext.getCiphertext;
import static java.util.stream.Collectors.collectingAndThen;
import static java.util.stream.Collectors.toList;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.List;
import java.util.stream.IntStream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import ch.post.it.evoting.cryptoprimitives.HashService;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientMessage;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.Permutation;
import ch.post.it.evoting.cryptoprimitives.random.PermutationService;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.Generators;

@DisplayName("A ShuffleArgumentService")
class ShuffleArgumentServiceTest extends TestGroupSetup {

	private static final int KEY_ELEMENTS_NUMBER = 11;
	private static final RandomService randomService = new RandomService();
	private static final SecureRandom secureRandom = new SecureRandom();
	private static final PermutationService permutationService = new PermutationService(randomService);

	private static ElGamalGenerator elGamalGenerator;
	private static CommitmentKeyGenerator commitmentKeyGenerator;
	private static HashService hashService;

	@BeforeAll
	static void setUpAll() throws NoSuchAlgorithmException {
		elGamalGenerator = new ElGamalGenerator(gqGroup);
		commitmentKeyGenerator = new CommitmentKeyGenerator(gqGroup);
		hashService = new HashService(MessageDigest.getInstance("SHA-256"));
	}

	@Nested
	@DisplayName("constructed with")
	class ConstructorTest {

		private int k;
		private ElGamalMultiRecipientPublicKey publicKey;
		private CommitmentKey commitmentKey;

		@BeforeEach
		void setUp() {
			k = secureRandom.nextInt(KEY_ELEMENTS_NUMBER - 1) + 1;

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

		@Test
		@DisplayName("public and commitment keys of different size throws IllegalArgumentException")
		void constructPublicCommitmentKeysDiffSize() {
			final ElGamalMultiRecipientPublicKey longerPublicKey = elGamalGenerator.genRandomPublicKey(k + 1);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> new ShuffleArgumentService(longerPublicKey, commitmentKey, randomService, hashService));
			assertEquals("The commitment key and public key must be of the same size.", exception.getMessage());
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

			final HashService hashServiceMock = mock(HashService.class);
			when(hashServiceMock.recursiveHash(any())).thenReturn(new byte[] { 0b10 });
			shuffleArgumentService = new ShuffleArgumentService(publicKey, commitmentKey, randomService, hashServiceMock);
		}

		@BeforeEach
		void setUp() {
			// Because the test groups are small.
			do {
				m = secureRandom.nextInt(KEY_ELEMENTS_NUMBER - 1) + 1;
				n = secureRandom.nextInt(KEY_ELEMENTS_NUMBER - 1) + 1;
			} while (BigInteger.valueOf((long) m * n).compareTo(zqGroup.getQ()) >= 0);
			N = m * n;

			// Create a witness.
			final Permutation permutation = permutationService.genPermutation(N);
			final SameGroupVector<ZqElement, ZqGroup> randomness = zqGroupGenerator.genRandomZqElementVector(N);

			shuffleWitness = new ShuffleWitness(permutation, randomness);

			// Create the corresponding statement.
			l = secureRandom.nextInt(KEY_ELEMENTS_NUMBER - 1) + 1;
			final SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts = elGamalGenerator.genRandomCiphertextVector(N, l);

			final ElGamalMultiRecipientMessage ones = ElGamalMultiRecipientMessage.ones(l, gqGroup);
			final SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> shuffledCiphertexts = IntStream.range(0, N)
					.mapToObj(i -> getCiphertext(ones, randomness.get(i), publicKey)
							.multiply(ciphertexts.get(permutation.get(i))))
					.collect(collectingAndThen(toList(), SameGroupVector::new));

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
			final SameGroupVector<ZqElement, ZqGroup> longerRandomness = zqGroupGenerator.genRandomZqElementVector(N + 1);
			final ShuffleWitness longerShuffleWitness = new ShuffleWitness(longerPermutation, longerRandomness);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> shuffleArgumentService.getShuffleArgument(shuffleStatement, longerShuffleWitness, m, n));
			assertEquals("The statement ciphertexts must have the same size as the permutation.", exception.getMessage());
		}

		@Test
		@DisplayName("ciphertexts and randomness having a different group order throws IllegalArgumentException")
		void getShuffleArgumentCiphertextsRandomnessDiffOrder() {
			final SameGroupVector<ZqElement, ZqGroup> differentRandomness = otherZqGroupGenerator.genRandomZqElementVector(N);
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
			final SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> longerCiphertexts = elGamalGenerator
					.genRandomCiphertextVector(N, biggerL);

			final ElGamalMultiRecipientMessage ones = ElGamalMultiRecipientMessage.ones(biggerL, gqGroup);
			final SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> shuffledCiphertexts = IntStream.range(0, N)
					.mapToObj(i -> getCiphertext(ones, shuffleWitness.getRandomness().get(i), longerPublicKey)
							.multiply(longerCiphertexts.get(shuffleWitness.getPermutation().get(i))))
					.collect(collectingAndThen(toList(), SameGroupVector::new));

			final ShuffleStatement longerCiphertextsStatement = new ShuffleStatement(longerCiphertexts, shuffledCiphertexts);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> shuffleArgumentService.getShuffleArgument(longerCiphertextsStatement, shuffleWitness, m, n));
			assertEquals("The ciphertexts must be smaller than the public key.", exception.getMessage());
		}

		@Test
		@DisplayName("re-encrypted and shuffled ciphertexts C different C' throws IllegalArgumentException")
		void getShuffleArgumentCiphertextsShuffledCiphertextsDiff() {
			// Modify the shuffled ciphertexts by replacing its first element by a different ciphertext.
			final List<ElGamalMultiRecipientCiphertext> shuffledCiphertexts = shuffleStatement.getShuffledCiphertexts().stream().collect(toList());
			final ElGamalMultiRecipientCiphertext first = shuffledCiphertexts.get(0);
			final ElGamalMultiRecipientCiphertext otherFirst = Generators.genWhile(() -> elGamalGenerator.genRandomCiphertext(l), first::equals);
			shuffledCiphertexts.set(0, otherFirst);

			// Recreate shuffled ciphertexts and statement.
			final SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> differentShuffledCiphertexts = new SameGroupVector<>(
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

}