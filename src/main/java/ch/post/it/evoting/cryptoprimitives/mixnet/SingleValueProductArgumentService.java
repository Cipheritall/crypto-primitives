/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static ch.post.it.evoting.cryptoprimitives.mixnet.CommitmentService.getCommitment;
import static ch.post.it.evoting.cryptoprimitives.SameGroupVector.toSameGroupVector;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import ch.post.it.evoting.cryptoprimitives.ConversionService;
import ch.post.it.evoting.cryptoprimitives.HashService;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;

/**
 * Provides methods for calculating a single value product argument.
 */
class SingleValueProductArgumentService {

	private final RandomService randomService;
	private final HashService hashService;
	private final ElGamalMultiRecipientPublicKey publicKey;
	private final CommitmentKey commitmentKey;

	SingleValueProductArgumentService(final RandomService randomService, final HashService hashService,
			final ElGamalMultiRecipientPublicKey publicKey, final CommitmentKey commitmentKey) {
		this.randomService = checkNotNull(randomService);
		this.hashService = checkNotNull(hashService);
		this.publicKey = checkNotNull(publicKey);
		this.commitmentKey = checkNotNull(commitmentKey);
	}

	/**
	 * Computes a Single Value Product Argument.
	 *
	 * <p>Takes a statement - consisting of a commitment and a product - and
	 * a witness - consisting of elements (a<sub>0</sub>, ..., a<sub>n-1</sub>) and the commitment's randomness. The statement and witness must comply
	 * with the following:
	 * <ul>
	 *  <li>be non null</li>
	 *  <li>have the same order <i>q</i></li>
	 *  <li>commitment = getCommitment(elements, randomness, commitmentKey)</li>
	 *  <li>product = &prod;<sub>i=0</sub><sup>n-1</sup> a<sub>i</sub></li>
	 * </ul>
	 *
	 * @param statement the {@link SingleValueProductStatement} for the single value product argument
	 * @param witness   the {@link SingleValueProductWitness} for the single value product argument
	 * @return a {@link SingleValueProductArgument} computed from the input
	 */
	SingleValueProductArgument getSingleValueProductArgument(final SingleValueProductStatement statement, final SingleValueProductWitness witness) {
		// Null checks
		checkNotNull(statement);
		checkNotNull(witness);

		GqElement ca = statement.getCommitment();
		ZqElement b = statement.getProduct();
		SameGroupVector<ZqElement, ZqGroup> a = witness.getElements();
		ZqElement r = witness.getRandomness();

		// Check groups
		checkArgument(ca.getGroup().equals(commitmentKey.getGroup()),
				"The statement's groups must have the same order as the commitment key's group.");
		checkArgument(a.getGroup().getQ().equals(commitmentKey.getGroup().getQ()),
				"The witness' group must have the same order as the commitment key's group.");

		// Ensure that the statement corresponds to the witness
		checkArgument(ca.equals(getCommitment(a, r, commitmentKey)),
				"The provided commitment does not correspond to the elements, randomness and commitment key provided.");
		ZqGroup group = b.getGroup();
		ZqElement one = ZqElement.create(BigInteger.ONE, group); // Identity for multiplication
		checkArgument(b.equals(a.stream().reduce(one, ZqElement::multiply)),
				"The product of the provided elements does not give the provided product.");

		// Start of the algorithm
		int n = a.size();
		BigInteger q = group.getQ();

		// Calculate b_0, ..., b_(n-1)
		List<ZqElement> bList = IntStream.range(0, n)
				.mapToObj(k -> a.stream().limit(k + 1L).reduce(one, ZqElement::multiply))
				.collect(Collectors.toList());

		// Calculate d and r_d
		SameGroupVector<ZqElement, ZqGroup> d = Stream.generate(() -> randomService.genRandomInteger(q))
				.map(value -> ZqElement.create(value, group))
				.limit(n)
				.collect(toSameGroupVector());
		ZqElement rd = ZqElement.create(randomService.genRandomInteger(q), group);

		// Calculate δ
		List<ZqElement> lowerDelta = new ArrayList<>(n);
		lowerDelta.add(0, d.get(0));
		if (n > 1) {
			lowerDelta.addAll(1, Stream.generate(() -> randomService.genRandomInteger(q)).map(value -> ZqElement.create(value, group)).limit(n - 2L)
					.collect(Collectors.toList()));
			lowerDelta.add(n - 1, group.getIdentity());
		}

		// Calculate s_0 and s_x
		ZqElement s0 = ZqElement.create(randomService.genRandomInteger(q), group);
		ZqElement sx = ZqElement.create(randomService.genRandomInteger(q), group);

		// Calculate δ' and Δ
		SameGroupVector<ZqElement, ZqGroup> lowerDeltaPrime = IntStream.range(0, n - 1)
				.mapToObj(k -> lowerDelta.get(k).negate().multiply(d.get(k + 1)))
				.collect(toSameGroupVector());
		SameGroupVector<ZqElement, ZqGroup> upperDelta = IntStream.range(0, n - 1)
				.mapToObj(k -> lowerDelta.get(k + 1)
						.add(a.get(k + 1).negate().multiply(lowerDelta.get(k)))
						.add(bList.get(k).negate().multiply(d.get(k + 1))))
				.collect(toSameGroupVector());

		// Calculate c_d, c_δ and c_Δ
		GqElement cd = getCommitment(d, rd, commitmentKey);
		GqElement cLowerDelta = getCommitment(lowerDeltaPrime, s0, commitmentKey);
		GqElement cUpperDelta = getCommitment(upperDelta, sx, commitmentKey);

		// Calculate x
		byte[] hash = hashService.recursiveHash(publicKey.stream().map(GqElement::getValue).collect(Collectors.toList()),
				commitmentKey.stream().map(GqElement::getValue).collect(Collectors.toList()),
				cUpperDelta.getValue(),
				cLowerDelta.getValue(),
				cd.getValue(),
				b.getValue(),
				ca.getValue());
		ZqElement x = ZqElement.create(ConversionService.byteArrayToInteger(hash), group);

		// Calculate aTilde, bTilde, rTilde and sTilde
		SameGroupVector<ZqElement, ZqGroup> aTilde = IntStream.range(0, n)
				.mapToObj(k -> x.multiply(a.get(k)).add(d.get(k)))
				.collect(toSameGroupVector());
		SameGroupVector<ZqElement, ZqGroup> bTilde = IntStream.range(0, n)
				.mapToObj(k -> x.multiply(bList.get(k)).add(lowerDelta.get(k)))
				.collect(toSameGroupVector());
		ZqElement rTilde = x.multiply(r).add(rd);
		ZqElement sTilde = x.multiply(sx).add(s0);

		return new SingleValueProductArgument.SingleValueProductArgumentBuilder()
				.withCd(cd)
				.withCLowerDelta(cLowerDelta)
				.withCUpperDelta(cUpperDelta)
				.withATilde(aTilde)
				.withBTilde(bTilde)
				.withRTilde(rTilde)
				.withSTilde(sTilde)
				.build();
	}

	/**
	 * Verifies the correctness of a {@link SingleValueProductArgument} with respect to a given {@link SingleValueProductStatement}.
	 * <p>
	 * The statement and the argument must be non null and have compatible groups.
	 *
	 * @param statement the statement for which the argument is to be verified.
	 * @param argument  the argument to be verified.
	 * @return <b>true</b> if the argument is valid for the given statement, <b>false</b> otherwise
	 */
	boolean verifySingleValueProductArgument(final SingleValueProductStatement statement, final SingleValueProductArgument argument) {
		checkNotNull(statement);
		checkNotNull(argument);

		checkArgument(statement.getCommitment().getGroup().equals(argument.getCd().getGroup()),
				"The statement and the argument must have compatible groups.");

		// Retrieve elements for verification
		final GqElement ca = statement.getCommitment();
		final ZqElement b = statement.getProduct();
		final GqElement cd = argument.getCd();
		final GqElement cLowerDelta = argument.getCLowerDelta();
		final GqElement cUpperDelta = argument.getCUpperDelta();
		final SameGroupVector<ZqElement, ZqGroup> aTilde = argument.getATilde();
		final SameGroupVector<ZqElement, ZqGroup> bTilde = argument.getBTilde();
		final ZqElement rTilde = argument.getRTilde();
		final ZqElement sTilde = argument.getSTilde();

		final int n = aTilde.size();
		final ZqGroup zqGroup = b.getGroup();

		// Calculate x
		final byte[] hash = hashService.recursiveHash(publicKey.stream().map(GqElement::getValue).collect(Collectors.toList()),
				commitmentKey.stream().map(GqElement::getValue).collect(Collectors.toList()),
				cUpperDelta.getValue(),
				cLowerDelta.getValue(),
				cd.getValue(),
				b.getValue(),
				ca.getValue());
		final ZqElement x = ZqElement.create(ConversionService.byteArrayToInteger(hash), zqGroup);

		// Verify A
		final GqElement prodCa = ca.exponentiate(x).multiply(cd);
		final GqElement commA = getCommitment(aTilde, rTilde, commitmentKey);
		final boolean verifA = prodCa.equals(commA);

		// Verify Delta
		final GqElement prodDelta = cUpperDelta.exponentiate(x).multiply(cLowerDelta);
		final SameGroupVector<ZqElement, ZqGroup> eiVector = IntStream.range(0, n - 1)
				.mapToObj(i -> x.multiply(bTilde.get(i + 1))
						.add(bTilde.get(i).multiply(aTilde.get(i + 1).negate())))
				.collect(Collectors.collectingAndThen(Collectors.toList(), SameGroupVector::new));
		final GqElement commDelta = getCommitment(eiVector, sTilde, commitmentKey);
		final boolean verifDelta = prodDelta.equals(commDelta);

		// Verify B
		final boolean verifB = ((bTilde.get(0).equals(aTilde.get(0))) && (bTilde.get(n - 1).equals(x.multiply(b))));

		return verifA && verifDelta && verifB;
	}
}
