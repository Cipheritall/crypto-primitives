/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

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
		this.randomService = randomService;
		this.hashService = hashService;
		this.publicKey = publicKey;
		this.commitmentKey = commitmentKey;
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
		checkArgument(ca.equals(CommitmentService.getCommitment(a, r, commitmentKey)),
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
		lowerDelta.add(d.get(0));
		if(n > 1) {
			lowerDelta.addAll(Stream.generate(() -> randomService.genRandomInteger(q)).map(value -> ZqElement.create(value, group)).limit(n - 2L)
					.collect(Collectors.toList()));
			lowerDelta.add(d.get(n - 1));
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
		GqElement cd = CommitmentService.getCommitment(d, rd, commitmentKey);
		GqElement cLowerDelta = CommitmentService.getCommitment(lowerDeltaPrime, s0, commitmentKey);
		GqElement cUpperDelta = CommitmentService.getCommitment(upperDelta, sx, commitmentKey);

		// Calculate x
		byte[] hash = hashService.recursiveHash(publicKey.stream().map(GqElement::getValue).collect(Collectors.toList()),
				commitmentKey.stream().map(GqElement::getValue).collect(Collectors.toList()),
				cUpperDelta.getValue(),
				cLowerDelta.getValue(),
				cd.getValue(),
				b.getValue(),
				ca.getValue());
		BigInteger hashNumber = ConversionService.byteArrayToInteger(hash);
		ZqElement x = ZqElement.create(hashNumber, group);

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
				.withCLowerD(cd)
				.withCLowerDelta(cLowerDelta)
				.withCUpperDelta(cUpperDelta)
				.withATilde(aTilde)
				.withBTilde(bTilde)
				.withRTilde(rTilde)
				.withSTilde(sTilde)
				.build();
	}

}
