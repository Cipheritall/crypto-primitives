/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static ch.post.it.evoting.cryptoprimitives.SameGroupVector.toSameGroupVector;
import static ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext.getCiphertext;
import static ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext.getCiphertextVectorExponentiation;
import static ch.post.it.evoting.cryptoprimitives.mixnet.CommitmentService.getCommitment;
import static ch.post.it.evoting.cryptoprimitives.mixnet.CommitmentService.getCommitmentMatrix;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static java.util.stream.Collectors.collectingAndThen;
import static java.util.stream.Collectors.toList;

import java.math.BigInteger;
import java.util.List;
import java.util.function.IntFunction;
import java.util.stream.IntStream;
import java.util.stream.LongStream;
import java.util.stream.Stream;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.ConversionService;
import ch.post.it.evoting.cryptoprimitives.HashService;
import ch.post.it.evoting.cryptoprimitives.HashableBigInteger;
import ch.post.it.evoting.cryptoprimitives.SameGroupMatrix;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientMessage;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;

/**
 * Service to generate multi exponentiation arguments.
 */
final class MultiExponentiationArgumentService {

	private final ElGamalMultiRecipientPublicKey pk;
	private final CommitmentKey ck;
	private final RandomService randomService;
	private final HashService hashService;
	private final GqGroup gqGroup;
	private final ZqGroup zqGroup;

	/**
	 * Instantiate a new multi exponentiation argument service.
	 * <p>
	 * The parameters must abide by the following conditions:
	 * <ul>
	 *     <li>be non null</li>
	 *     <li>the public key and commitment key must be from the same group</li>
	 *     <li>the public key and commitment key must be of the same size</li>
	 * </ul>
	 *
	 * @param publicKey     the public key with which to encrypt ciphertexts
	 * @param commitmentKey the key used for commitments
	 * @param randomService the service providing randomness
	 * @param hashService   the service providing hashing
	 */
	MultiExponentiationArgumentService(final ElGamalMultiRecipientPublicKey publicKey, final CommitmentKey commitmentKey,
			final RandomService randomService, final HashService hashService) {

		//Null checking
		checkNotNull(publicKey);
		checkNotNull(commitmentKey);
		checkNotNull(randomService);
		checkNotNull(hashService);

		//Group checking
		checkArgument(publicKey.getGroup().equals(commitmentKey.getGroup()), "The public key and commitment key must belong to the same group");

		//Dimension checking
		checkArgument(publicKey.size() == commitmentKey.size(), "The commitment key and public key must be of the same size.");

		this.pk = publicKey;
		this.ck = commitmentKey;
		this.gqGroup = publicKey.getGroup();
		this.zqGroup = ZqGroup.sameOrderAs(gqGroup);
		this.randomService = randomService;
		this.hashService = hashService;
	}

	/**
	 * Generates a multi exponentiation proof using the statement and witness.
	 * <p>
	 * The statement and the witness must abide by the following conditions:
	 * <ul>
	 *     <li>be non null</li>
	 *     <li>the statement dimension m and n must be equal to the witness dimensions m and n</li>
	 *     <li>n must be smaller than the size of the public key</li>
	 * </ul>
	 *
	 * @param statement the statement, which must belong to the same Gq group as the public key and commitment key
	 * @param witness   the witness, which must belong to a Zq group of the same order as the public key and commitment key
	 */
	MultiExponentiationArgument getMultiExponentiationArgument(final MultiExponentiationStatement statement,
			final MultiExponentiationWitness witness) {

		//Null checking
		checkNotNull(statement);
		checkNotNull(witness);

		//Group checking
		checkArgument(this.gqGroup.equals(statement.getGroup()), "The statement and argument must belong to the same group.");
		checkArgument(this.gqGroup.hasSameOrderAs(witness.getGroup()), "The witness and argument must belong to groups of the same order.");
		BigInteger q = this.gqGroup.getQ();

		//Dimension checking
		SameGroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> CMatrix = statement.getCMatrix();
		ElGamalMultiRecipientCiphertext CCiphertext = statement.getC();
		SameGroupVector<GqElement, GqGroup> cA = statement.getcA();
		SameGroupMatrix<ZqElement, ZqGroup> AMatrix = witness.getA();
		SameGroupVector<ZqElement, ZqGroup> rVector = witness.getR();
		ZqElement rho = witness.getRho();

		checkArgument(statement.getDimensionN() == witness.getDimensionN(), "Statement and witness do not have compatible n dimension.");
		checkArgument(statement.getDimensionM() == witness.getDimensionM(), "Statement and witness do not have compatible m dimension.");
		checkArgument(witness.getDimensionN() <= pk.size(), "The number of rows of matrix A must be less than the size of the public key.");

		int m = statement.getDimensionM();
		int n = statement.getDimensionN();
		int l = CMatrix.isEmpty() ? 0 : CMatrix.get(0, 0).size();

		checkArgument(l <= pk.size(), "The ciphertexts must be smaller than the public key.");

		//Ensure that C is the result of the re-encryption and multi exponentiation of matrix C with exponents matrix A
		ElGamalMultiRecipientCiphertext computedCCiphertext = multiExponentiation(CMatrix, AMatrix, rho, m, l);
		checkArgument(CCiphertext.equals(computedCCiphertext),
				"The computed multi exponentiation ciphertext does not correspond to the one provided in the statement.");

		//Ensure that cA is the commitment to matrix A
		checkArgument(cA.equals(getCommitmentMatrix(AMatrix, rVector, ck)), "The commitment provided does not correspond to the matrix A.");

		//Algorithm
		//Generate a0, r0, bs, ss, taus,
		SameGroupVector<ZqElement, ZqGroup> a0 = new SameGroupVector<>(randomService.genRandomVector(q, n));
		ZqElement r0 = ZqElement.create(randomService.genRandomInteger(q), zqGroup);
		List<ZqElement> mutableBs = randomService.genRandomVector(q, 2 * m);
		List<ZqElement> mutableSs = randomService.genRandomVector(q, 2 * m);
		List<ZqElement> mutableTaus = randomService.genRandomVector(q, 2 * m);
		ZqElement zero = ZqElement.create(BigInteger.ZERO, zqGroup);
		mutableBs.set(m, zero);
		mutableSs.set(m, zero);
		mutableTaus.set(m, rho);
		SameGroupVector<ZqElement, ZqGroup> bVector = new SameGroupVector<>(mutableBs);
		SameGroupVector<ZqElement, ZqGroup> sVector = new SameGroupVector<>(mutableSs);
		SameGroupVector<ZqElement, ZqGroup> tauVector = new SameGroupVector<>(mutableTaus);

		//Compute cA0
		GqElement cA0 = getCommitment(a0, r0, ck);

		//Compute diagonal products
		SameGroupMatrix<ZqElement, ZqGroup> prependedAMatrix = AMatrix.prependColumn(a0);
		SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> diagonalProducts = getDiagonalProducts(CMatrix, prependedAMatrix);

		//Compute commitments to individual values of b
		SameGroupVector<GqElement, GqGroup> cBVector = IntStream.range(0, 2 * m)
				.mapToObj(k -> getCommitment(SameGroupVector.of(bVector.get(k)), sVector.get(k), ck))
				.collect(toSameGroupVector());

		//Compute re-encrypted diagonal products
		IntFunction<ElGamalMultiRecipientMessage> gPowBk =
				index -> Stream.generate(() -> gqGroup.getGenerator().exponentiate(bVector.get(index)))
						.limit(l)
						.collect(collectingAndThen(toList(), ElGamalMultiRecipientMessage::new));
		SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> EVector =
				IntStream.range(0, 2 * m)
						.mapToObj(k ->
								getCiphertext(gPowBk.apply(k), tauVector.get(k), pk)
										.multiply(diagonalProducts.get(k)))
						.collect(collectingAndThen(toList(), SameGroupVector::new));

		//Compute challenge hash
		byte[] hash = hashService.recursiveHash(
				HashableBigInteger.from(gqGroup.getP()),
				HashableBigInteger.from(gqGroup.getQ()),
				pk,
				ck,
				CMatrix,
				CCiphertext,
				cA,
				cA0,
				cBVector,
				EVector
		);
		ZqElement x = ZqElement.create(ConversionService.byteArrayToInteger(hash), zqGroup);

		//Compute as, r, b, s, tau
		ImmutableList<ZqElement> xPowI = LongStream.range(0, 2L * m)
				.mapToObj(BigInteger::valueOf)
				.map(x::exponentiate)
				.collect(toImmutableList());

		//For all the next computations we include the first element in the sum by starting at the index 0 instead of 1. This is possible since x^0
		// is 1.
		SameGroupVector<ZqElement, ZqGroup> neutralVector = Stream.generate(() -> zero)
				.limit(n)
				.collect(toSameGroupVector());
		SameGroupVector<ZqElement, ZqGroup> aVector = IntStream.range(0, m + 1)
				.mapToObj(i -> vectorScalarMultiplication(xPowI.get(i), prependedAMatrix.getColumn(i)))
				.reduce(neutralVector, MultiExponentiationArgumentService::vectorSum);

		SameGroupVector<ZqElement, ZqGroup> prependedrVector = rVector.prepend(r0);
		ZqElement r = IntStream.range(0, m + 1)
				.mapToObj(i -> xPowI.get(i).multiply(prependedrVector.get(i)))
				.reduce(zqGroup.getIdentity(), ZqElement::add);

		ZqElement b = IntStream.range(0, 2 * m)
				.mapToObj(k -> xPowI.get(k).multiply(bVector.get(k)))
				.reduce(zqGroup.getIdentity(), ZqElement::add);

		ZqElement s = IntStream.range(0, 2 * m)
				.mapToObj(k -> xPowI.get(k).multiply(sVector.get(k)))
				.reduce(zqGroup.getIdentity(), ZqElement::add);

		ZqElement tau = IntStream.range(0, 2 * m)
				.mapToObj(k -> xPowI.get(k).multiply(tauVector.get(k)))
				.reduce(zqGroup.getIdentity(), ZqElement::add);

		MultiExponentiationArgument.Builder builder = new MultiExponentiationArgument.Builder();
		return builder
				.withcA0(cA0)
				.withcBVector(cBVector)
				.withEVector(EVector)
				.withaVector(aVector)
				.withr(r)
				.withb(b)
				.withs(s)
				.withtau(tau)
				.build();
	}

	@VisibleForTesting
	ElGamalMultiRecipientCiphertext multiExponentiation(final SameGroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> CMatrix,
			final SameGroupMatrix<ZqElement, ZqGroup> AMatrix, final ZqElement rho, final int m, final int ciphertextSize) {

		final ElGamalMultiRecipientCiphertext neutralElement = ElGamalMultiRecipientCiphertext.neutralElement(ciphertextSize, gqGroup);
		//Due to 0 indexing the index i+1 in the spec on the matrix A becomes index i here
		final ElGamalMultiRecipientCiphertext multiExponentiationProduct = IntStream.range(0, m)
				.mapToObj(i -> getCiphertextVectorExponentiation(CMatrix.getRow(i), AMatrix.getColumn(i)))
				.reduce(neutralElement, ElGamalMultiRecipientCiphertext::multiply);

		final ElGamalMultiRecipientMessage ones = ElGamalMultiRecipientMessage.ones(ciphertextSize, gqGroup);
		final ElGamalMultiRecipientCiphertext onesCiphertext = getCiphertext(ones, rho, pk);
		return onesCiphertext.multiply(multiExponentiationProduct);
	}

	/**
	 * Computes the products of the diagonals of a ciphertext matrix.
	 * <p>
	 * The ciphertexts and exponents matrix must comply with the following:
	 * <ul>
	 *     <li>The ciphertexts matrix must have as many columns as the exponents matrix has rows</li>
	 *     <li>The exponents matrix must have one more column than the ciphertexts matrix has rows</li>
	 *     <li>The exponents group must have the order of the ciphertexts group</li>
	 *     <li>The ciphertexts' phis must not be larger than the elements in the public key</li>
	 *     <li>The ciphertexts and public key must be part of the same group</li>
	 * </ul>
	 *
	 * @param ciphertexts C, the ciphertexts matrix.
	 * @param exponents   A, the exponents matrix.
	 * @return A {@link SameGroupVector} of size 2m.
	 */
	@VisibleForTesting
	SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> getDiagonalProducts(
			final SameGroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts, final SameGroupMatrix<ZqElement, ZqGroup> exponents) {

		// Null checking.
		checkNotNull(ciphertexts);
		checkNotNull(exponents);

		// Empty matrices handling.
		checkArgument(!ciphertexts.isEmpty() && !exponents.isEmpty(), "The ciphertexts and exponents matrices can not be empty.");

		// Dimensions checking.
		checkArgument(ciphertexts.numColumns() == exponents.numRows(),
				"The ciphertexts matrix must have as many columns as the exponents matrix has rows.");
		checkArgument(ciphertexts.numRows() + 1 == exponents.numColumns(),
				"The exponents matrix must have one more column than the ciphertexts matrix has rows.");
		checkArgument(ciphertexts.get(0, 0).size() <= this.pk.size(),
				"There must be at least the same number of key elements than ciphertexts' phis.");
		checkArgument(ciphertexts.stream().map(ElGamalMultiRecipientCiphertext::size).distinct().count() <= 1,
				"All ciphertexts must have the same number of phis.");

		// Group checking.
		checkArgument(pk.getGroup().equals(ciphertexts.getGroup()), "The public key and ciphertexts matrices must be part of the same group.");
		checkArgument(ciphertexts.getGroup().getQ().equals(exponents.getGroup().getQ()),
				"The exponents group must have the order of the ciphertexts group.");

		// Algorithm.

		final int m = ciphertexts.numRows();
		final int l = ciphertexts.get(0, 0).size();

		// Corresponds to the dk of the specifications.
		final ElGamalMultiRecipientCiphertext ciphertextMultiplicationIdentity = ElGamalMultiRecipientCiphertext.neutralElement(l, gqGroup);

		// Compute the diagonal products D.
		return IntStream.range(0, 2 * m)
				.mapToObj(k -> {
					int lowerBound;
					int upperBound;
					if (k < m) {
						lowerBound = (m - k) - 1;
						upperBound = m;
					} else {
						lowerBound = 0;
						upperBound = 2 * m - k;
					}

					return IntStream.range(lowerBound, upperBound)
							.mapToObj(i -> {
								final int j = (k - m) + i + 1;
								final SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertextRowI = ciphertexts.getRow(i);
								final SameGroupVector<ZqElement, ZqGroup> exponentsColumnJ = exponents.getColumn(j);
								return ElGamalMultiRecipientCiphertext.getCiphertextVectorExponentiation(ciphertextRowI, exponentsColumnJ);
							})
							.reduce(ciphertextMultiplicationIdentity, ElGamalMultiRecipientCiphertext::multiply);
				})
				.collect(toSameGroupVector());
	}

	private static SameGroupVector<ZqElement, ZqGroup> vectorSum(SameGroupVector<ZqElement, ZqGroup> first,
			SameGroupVector<ZqElement, ZqGroup> second) {
		checkNotNull(first);
		checkNotNull(second);
		checkArgument(first.size() == second.size(), "Cannot sum vectors of different dimensions.");
		checkArgument(first.getGroup().equals(second.getGroup()), "Cannot sum vectors of different groups.");
		return IntStream.range(0, first.size())
				.mapToObj(i -> first.get(i).add(second.get(i)))
				.collect(toSameGroupVector());
	}

	private static SameGroupVector<ZqElement, ZqGroup> vectorScalarMultiplication(ZqElement value, SameGroupVector<ZqElement, ZqGroup> vector) {
		return vector.stream().map(element -> element.multiply(value)).collect(toSameGroupVector());
	}
}
