/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static ch.post.it.evoting.cryptoprimitives.mixnet.CommitmentService.getCommitment;
import static ch.post.it.evoting.cryptoprimitives.mixnet.CommitmentService.getCommitmentMatrix;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import ch.post.it.evoting.cryptoprimitives.HashService;
import ch.post.it.evoting.cryptoprimitives.SameGroupMatrix;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;

final class ProductArgumentService {

	private final RandomService randomService;
	private final HashService hashService;
	private final ElGamalMultiRecipientPublicKey publicKey;
	private final CommitmentKey commitmentKey;
	private final HadamardArgumentService hadamardArgumentService;
	private final SingleValueProductArgumentService singleValueProductArgumentService;

	/**
	 * Constructs a ProductArgumentService.
	 *
	 * @param randomService the random service to be used for random integer generation.
	 * @param hashService	the hash service that provides the recursive hash function to be used.
	 * @param publicKey		the public key.
	 * @param commitmentKey the commitment key to be used for commitments.
	 */
	ProductArgumentService(final RandomService randomService, final HashService hashService, final ElGamalMultiRecipientPublicKey publicKey,
			final CommitmentKey commitmentKey) {
		this.randomService = checkNotNull(randomService);
		this.hashService = checkNotNull(hashService);
		this.publicKey = checkNotNull(publicKey);
		this.commitmentKey = checkNotNull(commitmentKey);
		this.hadamardArgumentService = new HadamardArgumentService(this.randomService, this.hashService, this.publicKey, this.commitmentKey);
		this.singleValueProductArgumentService = new SingleValueProductArgumentService(this.randomService, this.hashService, this.publicKey,
				this.commitmentKey);

		// Group checking
		checkArgument(publicKey.getGroup().equals(commitmentKey.getGroup()),
				"The public key and the commitment key must have the same group.");
	}

	/**
	 * Calculates a {@link ProductArgument}.
	 * <p>
	 * The statement and witness must comply with the following:
	 * <ul>
	 *     <li>be non null</li>
	 *     <li>the commitments to matrix A and the exponent vector r must have the same size</li>
	 *     <li>the matrix' number of rows must not be greater than the commitment key size</li>
	 *     <li>the product b and the matrix A must belong to the same group</li>
	 *     <li>the commitments to A and the commitment key must belong to the same group</li>
	 *     <li>the matrix A must have two or more columns</li>
	 *     <li>c<sub>A</sub> = getCommitmentMatrix(A, r, ck)</li>
	 *     <li>b = &prod;<sub>i,j</sub> a<sub>i,j</sub> mod q</li>
	 * </ul>
	 *
	 * @param statement the {@link ProductStatement}
	 * @param witness	the {@link ProductWitness}
	 * @return a {@link ProductArgument}
	 */
	ProductArgument getProductArgument(final ProductStatement statement, final ProductWitness witness) {
		checkNotNull(statement);
		checkNotNull(witness);

		final SameGroupVector<GqElement, GqGroup> cA = statement.getCommitments();
		final ZqElement b = statement.getProduct();
		@SuppressWarnings("squid:S00117")
		final SameGroupMatrix<ZqElement, ZqGroup> A = witness.getMatrix();
		final SameGroupVector<ZqElement, ZqGroup> r = witness.getExponents();

		// Dimension check
		checkArgument(cA.size() == r.size(), "The commitments A and the exponents r must have the same size.");
		checkArgument(A.numRows() <= commitmentKey.size(),
				"The matrix' number of rows cannot be greater than the commitment key size.");

		// Group check
		checkArgument(b.getGroup().equals(A.getGroup()), "The product b and the matrix A must belong to the same group.");
		checkArgument(commitmentKey.getGroup().equals(cA.getGroup()), "The commitment key and the commitments must have the same group.");

		// Ensure that the statement and the witness are compatible
		final int n = A.numRows();
		final int m = A.numColumns();
		checkArgument(m >= 2, "The matrix A must have at least 2 columns.");
		checkArgument(cA.equals(getCommitmentMatrix(A, r, commitmentKey)),
				"The commitment to matrix A with exponents r using the given commitment key must yield the commitments cA.");
		final ZqGroup zqGroup = A.getGroup();
		// Create the neutral element for the multiplication
		final ZqElement one = ZqElement.create(BigInteger.ONE, zqGroup);
		checkArgument(b.equals(A.stream().reduce(one, ZqElement::multiply)), "The product of all elements in matrix A must be equal to b.");

		// Start of the operations
		final BigInteger q = zqGroup.getQ();
		final ZqElement s = ZqElement.create(randomService.genRandomInteger(q), zqGroup);
		final SameGroupVector<ZqElement, ZqGroup> biList = IntStream.range(0, n)
				.mapToObj(i -> IntStream.range(0, m)
						.mapToObj(j -> A.get(i, j))
						.reduce(one, ZqElement::multiply))
				.collect(Collectors.collectingAndThen(Collectors.toList(), SameGroupVector::new));
		final GqElement cb = getCommitment(biList, s, commitmentKey);

		// Get the Hadamard argument
		HadamardStatement hStatement = new HadamardStatement(cA, cb);
		HadamardWitness hWitness = new HadamardWitness(A, biList, r, s);
		HadamardArgument hadamardArgument = hadamardArgumentService.getHadamardArgument(hStatement, hWitness);

		// Get the single value product argument
		SingleValueProductStatement sStatement = new SingleValueProductStatement(cb, b);
		SingleValueProductWitness sWitness = new SingleValueProductWitness(biList, s);
		SingleValueProductArgument singleValueProdArgument = singleValueProductArgumentService.getSingleValueProductArgument(sStatement, sWitness);

		return new ProductArgument(cb, hadamardArgument, singleValueProdArgument);
	}
}
