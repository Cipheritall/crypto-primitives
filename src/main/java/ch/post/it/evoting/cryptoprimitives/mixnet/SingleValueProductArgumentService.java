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
@SuppressWarnings("java:S117")
class SingleValueProductArgumentService {

	private final RandomService randomService;
	private final HashService hashService;
	private final ElGamalMultiRecipientPublicKey pk;
	private final CommitmentKey ck;

	SingleValueProductArgumentService(final RandomService randomService, final HashService hashService,
			final ElGamalMultiRecipientPublicKey publicKey, final CommitmentKey commitmentKey) {
		this.randomService = checkNotNull(randomService);
		this.hashService = checkNotNull(hashService);
		this.pk = checkNotNull(publicKey);
		this.ck = checkNotNull(commitmentKey);

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

		final GqElement c_a = statement.get_c_a();
		final ZqElement b = statement.get_b();
		final GroupVector<ZqElement, ZqGroup> a = witness.get_a();
		final ZqElement r = witness.get_r();

		// Check groups
		checkArgument(c_a.getGroup().equals(ck.getGroup()),
				"The statement's groups must have the same order as the commitment key's group.");
		checkArgument(a.getGroup().hasSameOrderAs(ck.getGroup()),
				"The witness' group must have the same order as the commitment key's group.");

		// Ensure that the statement corresponds to the witness
		final int n = a.size();
		checkArgument(2 <= n, "The size n of the witness must be at least 2.");
		checkArgument(c_a.equals(getCommitment(a, r, ck)),
				"The provided commitment does not correspond to the elements, randomness and commitment key provided.");
		final ZqGroup zqGroup = b.getGroup();

		final ZqElement one = ZqElement.create(1, zqGroup); // Identity for multiplication
		checkArgument(b.equals(a.stream().reduce(one, ZqElement::multiply)),
				"The product of the provided elements does not give the provided product.");

		final GqGroup gqGroup = c_a.getGroup();
		final BigInteger q = gqGroup.getQ();
		final BigInteger p = gqGroup.getP();

		// Algorithm
		// Calculate b_0, ..., b_(n-1)
		final List<ZqElement> b_vector = IntStream.range(0, n)
				.mapToObj(k -> a.stream().limit(k + 1L).reduce(one, ZqElement::multiply))
				.collect(Collectors.toList());

		// Calculate d and r_d
		final GroupVector<ZqElement, ZqGroup> d = randomService.genRandomVector(q, n);
		final ZqElement r_d = ZqElement.create(randomService.genRandomInteger(q), zqGroup);

		// Calculate δ
		final List<ZqElement> delta_mutable = new ArrayList<>(n);
		delta_mutable.add(0, d.get(0));
		if (n > 2) {
			delta_mutable.addAll(1, randomService.genRandomVector(q, n - 2));
		}
		delta_mutable.add(n - 1, zqGroup.getIdentity());
		final GroupVector<ZqElement, ZqGroup> delta = GroupVector.from(delta_mutable);

		// Calculate s_0 and s_x
		final ZqElement s_0 = ZqElement.create(randomService.genRandomInteger(q), zqGroup);
		final ZqElement s_x = ZqElement.create(randomService.genRandomInteger(q), zqGroup);

		// Calculate δ' and Δ
		final GroupVector<ZqElement, ZqGroup> delta_prime = IntStream.range(0, n - 1)
				.mapToObj(k -> delta.get(k).negate().multiply(d.get(k + 1)))
				.collect(toGroupVector());
		final GroupVector<ZqElement, ZqGroup> Delta = IntStream.range(0, n - 1)
				.mapToObj(k -> delta.get(k + 1)
						.add(a.get(k + 1).negate().multiply(delta.get(k)))
						.add(b_vector.get(k).negate().multiply(d.get(k + 1))))
				.collect(toGroupVector());

		// Calculate c_d, c_δ and c_Δ
		final GqElement c_d = getCommitment(d, r_d, ck);
		final GqElement c_delta = getCommitment(delta_prime, s_0, ck);
		final GqElement c_Delta = getCommitment(Delta, s_x, ck);

		// Calculate x
		final byte[] x_bytes = hashService.recursiveHash(
				HashableBigInteger.from(p),
				HashableBigInteger.from(q),
				pk,
				ck,
				c_Delta,
				c_delta,
				c_d,
				b,
				c_a);

		final ZqElement x = ZqElement.create(ConversionService.byteArrayToInteger(x_bytes), zqGroup);

		// Calculate aTilde, bTilde, rTilde and sTilde
		final GroupVector<ZqElement, ZqGroup> a_tilde = IntStream.range(0, n)
				.mapToObj(k -> x.multiply(a.get(k)).add(d.get(k)))
				.collect(toGroupVector());
		final GroupVector<ZqElement, ZqGroup> b_tilde = IntStream.range(0, n)
				.mapToObj(k -> x.multiply(b_vector.get(k)).add(delta.get(k)))
				.collect(toGroupVector());
		final ZqElement r_tilde = x.multiply(r).add(r_d);
		final ZqElement s_tilde = x.multiply(s_x).add(s_0);

		return new SingleValueProductArgument.Builder()
				.with_c_d(c_d)
				.with_c_delta(c_delta)
				.with_c_Delta(c_Delta)
				.with_a_tilde(a_tilde)
				.with_b_tilde(b_tilde)
				.with_r_tilde(r_tilde)
				.with_s_tilde(s_tilde)
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

		checkArgument(statement.get_c_a().getGroup().equals(argument.get_c_d().getGroup()),
				"The statement and the argument must have compatible groups.");

		// Retrieve elements for verification
		final GqElement c_a = statement.get_c_a();
		final ZqElement b = statement.get_b();
		final GqElement c_d = argument.get_c_d();
		final GqElement c_delta = argument.get_c_delta();
		final GqElement c_Delta = argument.get_c_Delta();
		final GroupVector<ZqElement, ZqGroup> a_tilde = argument.get_a_tilde();
		final GroupVector<ZqElement, ZqGroup> b_tilde = argument.get_b_tilde();
		final ZqElement r_tilde = argument.get_r_tilde();
		final ZqElement s_tilde = argument.get_s_tilde();

		final int n = a_tilde.size();
		final GqGroup gqGroup = c_a.getGroup();
		final BigInteger p = gqGroup.getP();
		final BigInteger q = gqGroup.getQ();
		final ZqGroup zqGroup = b.getGroup();

		// Calculate x
		final byte[] x_bytes = hashService.recursiveHash(
				HashableBigInteger.from(p),
				HashableBigInteger.from(q),
				pk,
				ck,
				c_Delta,
				c_delta,
				c_d,
				b,
				c_a);
		final ZqElement x = ZqElement.create(ConversionService.byteArrayToInteger(x_bytes), zqGroup);

		// Verify A
		final GqElement prodCa = c_a.exponentiate(x).multiply(c_d);
		final GqElement commA = getCommitment(a_tilde, r_tilde, ck);
		final Verifiable verifA = create(() -> prodCa.equals(commA), String.format("prodCa %s and commA %s are not equal", prodCa, commA));

		// Verify Delta
		final GqElement prodDelta = c_Delta.exponentiate(x).multiply(c_delta);
		final GroupVector<ZqElement, ZqGroup> e = IntStream.range(0, n - 1)
				.mapToObj(i -> x.multiply(b_tilde.get(i + 1))
						.subtract(b_tilde.get(i).multiply(a_tilde.get(i + 1))))
				.collect(toGroupVector());
		final GqElement commDelta = getCommitment(e, s_tilde, ck);
		final Verifiable verifDelta = create(() -> prodDelta.equals(commDelta),
				String.format("prodDelta %s and commDelta %s are not equal", prodDelta, commDelta));

		// Verify B
		final Verifiable verifB = create(() -> b_tilde.get(0).equals(a_tilde.get(0)) && b_tilde.get(n - 1).equals(x.multiply(b)),
				String.format("bTilde.get(0) %s must equal aTilde.get(0) %s and bTilde.get(n - 1) %s must equal x * b %s", b_tilde.get(0),
						a_tilde.get(0), b_tilde.get(n - 1), x.multiply(b)));

		return verifA.and(verifDelta).and(verifB);
	}

}
