/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static ch.post.it.evoting.cryptoprimitives.SameGroupVector.toSameGroupVector;
import static ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext.getCiphertext;
import static ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext.getCiphertextVectorExponentiation;
import static ch.post.it.evoting.cryptoprimitives.mixnet.CommitmentService.getCommitmentMatrix;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static java.util.stream.Collectors.collectingAndThen;
import static java.util.stream.Collectors.toList;

import java.math.BigInteger;
import java.util.List;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import ch.post.it.evoting.cryptoprimitives.ConversionService;
import ch.post.it.evoting.cryptoprimitives.HashService;
import ch.post.it.evoting.cryptoprimitives.HashableBigInteger;
import ch.post.it.evoting.cryptoprimitives.HashableString;
import ch.post.it.evoting.cryptoprimitives.SameGroupMatrix;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientMessage;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.Permutation;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;

/**
 * Service to compute a cryptographic argument for the validity of a shuffle.
 */
class ShuffleArgumentService {

	private final ElGamalMultiRecipientPublicKey publicKey;
	private final CommitmentKey commitmentKey;

	private final RandomService randomService;
	private final HashService hashService;
	private final ProductArgumentService productArgumentService;
	private final MultiExponentiationArgumentService multiExponentiationArgumentService;

	/**
	 * Instantiates a ShuffleArgumentService with required context.
	 *
	 * @param publicKey     pk, the public key used in the recursive hash.
	 * @param commitmentKey ck, the commitment key used to compute commitments.
	 */
	ShuffleArgumentService(final ElGamalMultiRecipientPublicKey publicKey, final CommitmentKey commitmentKey, final RandomService randomService,
			final HashService hashService) {

		// Null checking.
		checkNotNull(publicKey);
		checkNotNull(commitmentKey);
		checkNotNull(randomService);
		checkNotNull(hashService);

		// Group checking.
		checkArgument(publicKey.getGroup().equals(commitmentKey.getGroup()), "The public key and commitment key must belong to the same group.");

		// Dimension checking.
		checkArgument(publicKey.size() == commitmentKey.size(), "The commitment key and public key must be of the same size.");

		this.publicKey = publicKey;
		this.commitmentKey = commitmentKey;
		this.randomService = randomService;
		this.hashService = hashService;
		this.productArgumentService = new ProductArgumentService(randomService, hashService, publicKey, commitmentKey);
		this.multiExponentiationArgumentService = new MultiExponentiationArgumentService(publicKey, commitmentKey, randomService, hashService);
	}

	/**
	 * Computes a cryptographic argument for the validity of the shuffle. The statement and witness must comply with the following:
	 *
	 * <ul>
	 *     <li>be non null</li>
	 *     <li>the statement and witness values must have the same size</li>
	 *     <li>the statement's ciphertexts group and the witness's randomness group must be of the same order</li>
	 *     <li>re-encrypting and shuffling the statement ciphertexts C with the witness randomness and permutation must give the statement
	 *     ciphertexts C'</li>
	 *     <li>the size N of all inputs must satisfy N = m * n</li>
	 * </ul>
	 *
	 * @param statement the {@link ShuffleStatement} for the shuffle argument.
	 * @param witness   the {@link ShuffleWitness} for the shuffle argument.
	 * @param m         the number of rows to use for ciphertext matrices. Strictly positive integer.
	 * @param n         the number of columns to use for ciphertext matrices. Strictly positive integer.
	 * @return a {@link ShuffleArgument}.
	 */
	ShuffleArgument getShuffleArgument(final ShuffleStatement statement, final ShuffleWitness witness, final int m, final int n) {
		checkNotNull(statement);
		checkNotNull(witness);

		checkArgument(m > 0, "The number of rows for the ciphertext matrices must be strictly positive.");
		checkArgument(n > 0, "The number of columns for the ciphertext matrices must be strictly positive.");

		final SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertextsC = statement.getCiphertexts();
		final SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> shuffledCiphertextsCprime = statement.getShuffledCiphertexts();
		final Permutation permutation = witness.getPermutation();
		final SameGroupVector<ZqElement, ZqGroup> randomness = witness.getRandomness();

		// Cross dimensions checking.
		checkArgument(ciphertextsC.size() == permutation.getSize(),
				"The statement ciphertexts must have the same size as the permutation.");

		// Cross group checking.
		checkArgument(ciphertextsC.getGroup().hasSameOrderAs(randomness.getGroup()),
				"The randomness group must have the order of the ciphertexts group.");

		// Ensure the statement corresponds to the witness.
		final GqGroup gqGroup = ciphertextsC.getGroup();
		final ZqGroup zqGroup = randomness.getGroup();
		final int N = permutation.getSize();
		final int l = ciphertextsC.get(0).size();

		checkArgument(l <= publicKey.size(), "The ciphertexts must be smaller than the public key.");

		final ElGamalMultiRecipientMessage ones = ElGamalMultiRecipientMessage.ones(l, gqGroup);
		final List<ElGamalMultiRecipientCiphertext> encryptedOnes = randomness.stream()
				.map(rho -> getCiphertext(ones, rho, publicKey))
				.collect(toList());
		final List<ElGamalMultiRecipientCiphertext> shuffledCiphertexts = permutation.stream()
				.mapToObj(ciphertextsC::get)
				.collect(toList());
		final SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> computedShuffledCiphertextsCprime = IntStream.range(0, N)
				.mapToObj(i -> encryptedOnes.get(i).multiply(shuffledCiphertexts.get(i)))
				.collect(toSameGroupVector());
		checkArgument(shuffledCiphertextsCprime.equals(computedShuffledCiphertextsCprime),
				"The shuffled ciphertexts provided in the statement do not correspond to the re-encryption and shuffle of C under pi and rho.");

		checkArgument(N == n * m, String.format("The ciphertexts vectors must be decomposable into m * n matrices: %d != %d * %d.", N, m, n));

		// Algorithm operations.

		final BigInteger p = gqGroup.getP();
		final BigInteger q = gqGroup.getQ();

		// Compute vector r, matrix A and vector c_A
		final SameGroupVector<ZqElement, ZqGroup> r = new SameGroupVector<>(randomService.genRandomVector(q, m));
		final SameGroupVector<ZqElement, ZqGroup> permutationVector = permutation.stream()
				.mapToObj(BigInteger::valueOf)
				.map(value -> ZqElement.create(value, zqGroup))
				.collect(toSameGroupVector());
		final SameGroupMatrix<ZqElement, ZqGroup> matrixA = permutationVector.toExponentMatrix(n, m);
		final SameGroupVector<GqElement, GqGroup> cA = getCommitmentMatrix(matrixA, r, commitmentKey);

		// Compute x.
		final byte[] xHash = hashService.recursiveHash(
				HashableBigInteger.from(p),
				HashableBigInteger.from(q),
				publicKey,
				commitmentKey,
				ciphertextsC,
				shuffledCiphertextsCprime,
				cA
		);
		final ZqElement x = ZqElement.create(ConversionService.byteArrayToInteger(xHash), zqGroup);

		// Compute vector s, vector b, matrix B and vector c_B.
		final SameGroupVector<ZqElement, ZqGroup> s = new SameGroupVector<>(randomService.genRandomVector(q, m));
		final SameGroupVector<ZqElement, ZqGroup> bVector = permutation.stream()
				.mapToObj(BigInteger::valueOf)
				.map(x::exponentiate)
				.collect(toSameGroupVector());
		final SameGroupMatrix<ZqElement, ZqGroup> matrixB = bVector.toExponentMatrix(n, m);
		final SameGroupVector<GqElement, GqGroup> cB = getCommitmentMatrix(matrixB, s, commitmentKey);

		// Compute y.
		final byte[] yHash = hashService.recursiveHash(
				cB,
				HashableBigInteger.from(p),
				HashableBigInteger.from(q),
				publicKey,
				commitmentKey,
				ciphertextsC,
				shuffledCiphertextsCprime,
				cA
		);
		final ZqElement y = ZqElement.create(ConversionService.byteArrayToInteger(yHash), zqGroup);

		// Compute z.
		final byte[] zHash = hashService.recursiveHash(
				HashableString.from("1"),
				cB,
				HashableBigInteger.from(p),
				HashableBigInteger.from(q),
				publicKey,
				commitmentKey,
				ciphertextsC,
				shuffledCiphertextsCprime,
				cA
		);
		final ZqElement z = ZqElement.create(ConversionService.byteArrayToInteger(zHash), zqGroup);

		// Compute Zneg, c_{-z}.
		final SameGroupMatrix<ZqElement, ZqGroup> negativeZ = Stream.generate(z::negate)
				.limit(N)
				.collect(toSameGroupVector())
				.toExponentMatrix(n, m);
		final SameGroupVector<ZqElement, ZqGroup> zeros = Stream.generate(zqGroup::getIdentity).limit(m).collect(toSameGroupVector());
		final SameGroupVector<GqElement, GqGroup> cNegativeZ = getCommitmentMatrix(negativeZ, zeros, commitmentKey);

		// Compute c_D.
		final List<GqElement> cD = IntStream.range(0, cA.size())
				.mapToObj(i -> cA.get(i).exponentiate(y).multiply(cB.get(i)))
				.collect(toList());

		// Compute matrix D.
		final SameGroupMatrix<ZqElement, ZqGroup> yTimesA = matrixA.stream()
				.map(y::multiply)
				.collect(collectingAndThen(toList(), SameGroupVector::new))
				.toExponentMatrix(matrixA.numRows(), matrixB.numColumns());
		final SameGroupMatrix<ZqElement, ZqGroup> matrixD = matrixSum(yTimesA, matrixB);

		// Compute vector t.
		final SameGroupVector<ZqElement, ZqGroup> t = IntStream.range(0, r.size())
				.mapToObj(i -> y.multiply(r.get(i)).add(s.get(i)))
				.collect(toSameGroupVector());

		// Pre-compute x^i for i=0..N use multiple times.
		final SameGroupVector<ZqElement, ZqGroup> xPowers = IntStream.range(0, N)
				.mapToObj(BigInteger::valueOf)
				.map(x::exponentiate)
				.collect(toSameGroupVector());

		// Compute b.
		final ZqElement b = IntStream.range(0, N)
				.boxed()
				.flatMap(i -> Stream.of(i)
						.map(BigInteger::valueOf)
						.map(bi -> ZqElement.create(bi, zqGroup))
						.map(y::multiply)
						.map(elem -> elem.add(xPowers.get(i)))
						.map(elem -> elem.subtract(z)))
				.reduce(ZqElement.create(BigInteger.ONE, zqGroup), ZqElement::multiply);

		// Compute pStatement.
		final SameGroupVector<GqElement, GqGroup> pStatementCommitments = IntStream.range(0, cD.size())
				.mapToObj(i -> cD.get(i).multiply(cNegativeZ.get(i)))
				.collect(toSameGroupVector());
		final ProductStatement pStatement = new ProductStatement(pStatementCommitments, b);

		// Compute pWitness.
		final SameGroupMatrix<ZqElement, ZqGroup> pWitnessMatrix = matrixSum(matrixD, negativeZ);
		final ProductWitness pWitness = new ProductWitness(pWitnessMatrix, t);

		// Compute productArgument.
		final ProductArgument productArgument = productArgumentService.getProductArgument(pStatement, pWitness);

		// Compute rho. The vector x is computed previously as xPowers.
		final ZqElement rho = IntStream.range(0, randomness.size())
				.mapToObj(i -> randomness.get(i).multiply(bVector.get(i)))
				.reduce(zqGroup.getIdentity(), ZqElement::add)
				.negate();

		// Compute ciphertext C.
		final ElGamalMultiRecipientCiphertext ciphertextC = getCiphertextVectorExponentiation(ciphertextsC, xPowers);

		// Compute mStatement.
		final MultiExponentiationStatement mStatement = new MultiExponentiationStatement(shuffledCiphertextsCprime.toCiphertextMatrix(m, n),
				ciphertextC, cB);

		// Compute mWitness.
		final MultiExponentiationWitness mWitness = new MultiExponentiationWitness(matrixB, s, rho);

		// Compute multiExponentiationArgument.
		final MultiExponentiationArgument multiExponentiationArgument = multiExponentiationArgumentService
				.getMultiExponentiationArgument(mStatement, mWitness);

		final ShuffleArgument.Builder builder = new ShuffleArgument.Builder();
		return builder
				.withCA(cA)
				.withCB(cB)
				.withProductArgument(productArgument)
				.withMultiExponentiationArgument(multiExponentiationArgument)
				.build();
	}

	private SameGroupMatrix<ZqElement, ZqGroup> matrixSum(final SameGroupMatrix<ZqElement, ZqGroup> first,
			final SameGroupMatrix<ZqElement, ZqGroup> second) {

		checkNotNull(first);
		checkNotNull(second);
		checkArgument(first.numRows() == second.numRows());
		checkArgument(first.numColumns() == second.numColumns());
		checkArgument(first.getGroup().equals(second.getGroup()));

		return IntStream.range(0, first.numRows())
				.mapToObj(i -> IntStream.range(0, first.numColumns())
						.mapToObj(j -> first.get(i, j).add(second.get(i, j)))
						.collect(toList()))
				.collect(collectingAndThen(toList(), SameGroupMatrix::fromRows));
	}

}
