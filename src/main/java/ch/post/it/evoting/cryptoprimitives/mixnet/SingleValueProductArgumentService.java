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
import static ch.post.it.evoting.cryptoprimitives.mixnet.CommitmentService.getCommitment;
import static ch.post.it.evoting.cryptoprimitives.mixnet.Verifiable.create;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.ConversionService;
import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableBigInteger;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

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

		// Check hash length
		final BigInteger q = publicKey.getGroup().getQ();
		checkArgument(hashService.getHashLength() * Byte.SIZE < q.bitLength(),
				"The hash service's bit length must be smaller than the bit length of q.");
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

		final GqElement ca = statement.getCommitment();
		final ZqElement b = statement.getProduct();
		final GroupVector<ZqElement, ZqGroup> a = witness.getElements();
		final ZqElement r = witness.getRandomness();

		// Check groups
		checkArgument(ca.getGroup().equals(commitmentKey.getGroup()),
				"The statement's groups must have the same order as the commitment key's group.");
		checkArgument(a.getGroup().hasSameOrderAs(commitmentKey.getGroup()),
				"The witness' group must have the same order as the commitment key's group.");

		// Ensure that the statement corresponds to the witness
		final int n = a.size();
		checkArgument(2 <= n, "The size n of the witness must be at least 2.");
		checkArgument(ca.equals(getCommitment(a, r, commitmentKey)),
				"The provided commitment does not correspond to the elements, randomness and commitment key provided.");
		final ZqGroup group = b.getGroup();

		final ZqElement one = ZqElement.create(1, group); // Identity for multiplication
		checkArgument(b.equals(a.stream().reduce(one, ZqElement::multiply)),
				"The product of the provided elements does not give the provided product.");

		// Start of the algorithm
		final BigInteger q = group.getQ();

		// Calculate b_0, ..., b_(n-1)
		final List<ZqElement> bList = IntStream.range(0, n)
				.mapToObj(k -> a.stream().limit(k + 1L).reduce(one, ZqElement::multiply))
				.collect(Collectors.toList());

		// Calculate d and r_d
		final GroupVector<ZqElement, ZqGroup> d = randomService.genRandomVector(q, n);
		final ZqElement rd = ZqElement.create(randomService.genRandomInteger(q), group);

		// Calculate δ
		final List<ZqElement> lowerDeltaElements = new ArrayList<>(n);
		lowerDeltaElements.add(0, d.get(0));
		if (n > 2) {
			lowerDeltaElements.addAll(1, randomService.genRandomVector(q, n - 2));
		}
		lowerDeltaElements.add(n - 1, group.getIdentity());
		final ImmutableList<ZqElement> lowerDelta = ImmutableList.copyOf(lowerDeltaElements);

		// Calculate s_0 and s_x
		final ZqElement s0 = ZqElement.create(randomService.genRandomInteger(q), group);
		final ZqElement sx = ZqElement.create(randomService.genRandomInteger(q), group);

		// Calculate δ' and Δ
		final GroupVector<ZqElement, ZqGroup> lowerDeltaPrime = IntStream.range(0, n - 1)
				.mapToObj(k -> lowerDelta.get(k).negate().multiply(d.get(k + 1)))
				.collect(toGroupVector());
		final GroupVector<ZqElement, ZqGroup> upperDelta = IntStream.range(0, n - 1)
				.mapToObj(k -> lowerDelta.get(k + 1)
						.add(a.get(k + 1).negate().multiply(lowerDelta.get(k)))
						.add(bList.get(k).negate().multiply(d.get(k + 1))))
				.collect(toGroupVector());

		// Calculate c_d, c_δ and c_Δ
		final GqElement cd = getCommitment(d, rd, commitmentKey);
		final GqElement cLowerDelta = getCommitment(lowerDeltaPrime, s0, commitmentKey);
		final GqElement cUpperDelta = getCommitment(upperDelta, sx, commitmentKey);

		// Calculate x
		final ZqElement x = hashAndConvertX(cUpperDelta, cLowerDelta, cd, b, ca);

		// Calculate aTilde, bTilde, rTilde and sTilde
		final GroupVector<ZqElement, ZqGroup> aTilde = IntStream.range(0, n)
				.mapToObj(k -> x.multiply(a.get(k)).add(d.get(k)))
				.collect(toGroupVector());
		final GroupVector<ZqElement, ZqGroup> bTilde = IntStream.range(0, n)
				.mapToObj(k -> x.multiply(bList.get(k)).add(lowerDelta.get(k)))
				.collect(toGroupVector());
		final ZqElement rTilde = x.multiply(r).add(rd);
		final ZqElement sTilde = x.multiply(sx).add(s0);

		return new SingleValueProductArgument.Builder()
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
	 * @return a {@link VerificationResult} being valid iff the argument is valid for the given statement.
	 */
	Verifiable verifySingleValueProductArgument(final SingleValueProductStatement statement, final SingleValueProductArgument argument) {
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
		final GroupVector<ZqElement, ZqGroup> aTilde = argument.getATilde();
		final GroupVector<ZqElement, ZqGroup> bTilde = argument.getBTilde();
		final ZqElement rTilde = argument.getRTilde();
		final ZqElement sTilde = argument.getSTilde();

		final int n = aTilde.size();

		// Calculate x
		final ZqElement x = hashAndConvertX(cUpperDelta, cLowerDelta, cd, b, ca);

		// Verify A
		final GqElement prodCa = ca.exponentiate(x).multiply(cd);
		final GqElement commA = getCommitment(aTilde, rTilde, commitmentKey);
		final Verifiable verifA = create(() -> prodCa.equals(commA), String.format("prodCa %s and commA %s are not equal", prodCa, commA));

		// Verify Delta
		final GqElement prodDelta = cUpperDelta.exponentiate(x).multiply(cLowerDelta);
		final GroupVector<ZqElement, ZqGroup> eiVector = IntStream.range(0, n - 1)
				.mapToObj(i -> x.multiply(bTilde.get(i + 1))
						.subtract(bTilde.get(i).multiply(aTilde.get(i + 1))))
				.collect(Collectors.collectingAndThen(Collectors.toList(), GroupVector::from));
		final GqElement commDelta = getCommitment(eiVector, sTilde, commitmentKey);
		final Verifiable verifDelta = create(() -> prodDelta.equals(commDelta),
				String.format("prodDelta %s and commDelta %s are not equal", prodDelta, commDelta));

		// Verify B
		final Verifiable verifB = create(() -> bTilde.get(0).equals(aTilde.get(0)) && bTilde.get(n - 1).equals(x.multiply(b)),
				String.format("bTilde.get(0) %s must equal aTilde.get(0) %s and bTilde.get(n - 1) %s must equal x * b %s", bTilde.get(0),
						aTilde.get(0), bTilde.get(n - 1), x.multiply(b)));

		return verifA.and(verifDelta).and(verifB);
	}

	private ZqElement hashAndConvertX(final GqElement cUpperDelta, final GqElement cLowerDelta, final GqElement cd, final ZqElement b,
			final GqElement ca) {
		final GqGroup gqGroup = ca.getGroup();
		final ZqGroup zqGroup = b.getGroup();
		final BigInteger p = gqGroup.getP();
		final BigInteger q = gqGroup.getQ();

		final byte[] hash = hashService.recursiveHash(
				HashableBigInteger.from(p),
				HashableBigInteger.from(q),
				publicKey,
				commitmentKey,
				cUpperDelta,
				cLowerDelta,
				cd,
				b,
				ca);

		return ZqElement.create(ConversionService.byteArrayToInteger(hash), zqGroup);
	}
}
