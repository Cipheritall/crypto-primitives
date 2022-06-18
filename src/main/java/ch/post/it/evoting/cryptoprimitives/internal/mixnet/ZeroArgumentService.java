/*
 * Copyright 2022 Post CH Ltd
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
package ch.post.it.evoting.cryptoprimitives.internal.mixnet;

import static ch.post.it.evoting.cryptoprimitives.internal.mixnet.CommitmentService.getCommitment;
import static ch.post.it.evoting.cryptoprimitives.internal.mixnet.CommitmentService.getCommitmentMatrix;
import static ch.post.it.evoting.cryptoprimitives.internal.mixnet.CommitmentService.getCommitmentVector;
import static ch.post.it.evoting.cryptoprimitives.internal.utils.ConversionsInternal.byteArrayToInteger;
import static ch.post.it.evoting.cryptoprimitives.internal.utils.Verifiable.create;
import static ch.post.it.evoting.cryptoprimitives.math.GroupVector.toGroupVector;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import com.google.common.annotations.VisibleForTesting;

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableBigInteger;
import ch.post.it.evoting.cryptoprimitives.internal.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.internal.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.internal.utils.Verifiable;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupMatrix;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.mixnet.ZeroArgument;
import ch.post.it.evoting.cryptoprimitives.mixnet.ZeroStatement;
import ch.post.it.evoting.cryptoprimitives.mixnet.ZeroWitness;
import ch.post.it.evoting.cryptoprimitives.utils.VerificationResult;

/**
 * Class in charge of providing a Zero Argument used in the Zero Argument proof.
 *
 * <p>This class is thread safe.</p>
 */
@SuppressWarnings("java:S117")
final class ZeroArgumentService {

	private final ElGamalMultiRecipientPublicKey pk;
	private final CommitmentKey ck;

	private final RandomService randomService;
	private final HashService hashService;

	ZeroArgumentService(final ElGamalMultiRecipientPublicKey publicKey, final CommitmentKey commitmentKey,
			final RandomService randomService, final HashService hashService) {

		// Null checking.
		checkNotNull(publicKey);
		checkNotNull(commitmentKey);
		checkNotNull(randomService);
		checkNotNull(hashService);

		// Group checking.
		checkArgument(publicKey.getGroup().equals(commitmentKey.getGroup()), "The public and commitment keys are not from the same group.");

		// Check hash length
		final BigInteger q = publicKey.getGroup().getQ();
		checkArgument(hashService.getHashLength() * Byte.SIZE < q.bitLength(),
				"The hash service's bit length must be smaller than the bit length of q.");

		this.pk = publicKey;
		this.ck = commitmentKey;
		this.randomService = randomService;
		this.hashService = hashService;
	}

	/**
	 * Generates an argument of knowledge of the values <code>a<sub>1</sub>, b<sub>0</sub>, ..., a<sub>m</sub>, b<sub>m-1</sub></code> such that
	 * &sum;<sub>i=1</sub><sup>m</sup> a<sub>i</sub> &#8902; b<sub>i-1</sub> = 0. The statement and witness must comply with the following:
	 * <ul>
	 *  <li>be non null</li>
	 *  <li>commitments must have the same size as the exponents</li>
	 *  <li>y must be part of the same group as the exponents elements</li>
	 *  <li>c<sub>A</sub> = getCommitmentMatrix(A, r, commitmentKey)</li>
	 *  <li>c<sub>B</sub> = getCommitmentMatrix(B, s, commitmentKey)</li>
	 *  <li>&sum;<sub>i=1</sub><sup>m</sup> a<sub>i</sub> &#8902; b<sub>i-1</sub> = 0</li>
	 * </ul>
	 *
	 * @param statement The zero argument statement.
	 * @param witness   The zero argument witness.
	 * @return The argument of knowledge as a {@link ZeroArgument}.
	 */
	ZeroArgument getZeroArgument(final ZeroStatement statement, final ZeroWitness witness) {
		// Null checking.
		checkNotNull(statement);
		checkNotNull(witness);

		final GroupMatrix<ZqElement, ZqGroup> A = witness.get_A();
		final GroupMatrix<ZqElement, ZqGroup> B = witness.get_B();
		final GroupVector<ZqElement, ZqGroup> r = witness.get_r();
		final GroupVector<ZqElement, ZqGroup> s = witness.get_s();
		final GroupVector<GqElement, GqGroup> c_A = statement.get_c_A();
		final GroupVector<GqElement, GqGroup> c_B = statement.get_c_B();
		final ZqElement y = statement.get_y();

		// Cross dimensions checking between statement and witness.
		checkArgument(statement.get_m() == witness.get_m(), "The statement and witness must have the same dimension m.");

		// Cross group checking.
		checkArgument(statement.getGroup().hasSameOrderAs(witness.getGroup()), "The statement and witness must have compatible groups.");

		// Ensure the statement and witness are corresponding.
		final GroupVector<GqElement, GqGroup> c_A_computed = getCommitmentMatrix(A, r, ck);
		checkArgument(c_A.equals(c_A_computed), "The statement's Ca commitments must be equal to the witness' commitment matrix A.");
		final GroupVector<GqElement, GqGroup> c_B_computed = getCommitmentMatrix(B, s, ck);
		checkArgument(c_B.equals(c_B_computed), "The statement's Cb commitments must be equal to the witness' commitment matrix B.");

		// The specifications uses the indices [1,m] for matrixA and [0,m-1] for matrixB. In the code, we use [0,m-1] for both indices.
		final ZqGroup zqGroup = y.getGroup();
		final BigInteger q = zqGroup.getQ();
		final int m = A.numColumns();
		final ZqElement starMapSum = IntStream.range(0, m)
				.mapToObj(i -> starMap(A.getColumn(i), B.getColumn(i), y))
				.reduce(zqGroup.getIdentity(), ZqElement::add);
		checkArgument(zqGroup.getIdentity().equals(starMapSum),
				"The sum of the starMap operations between the witness's matrices columns is not equal to 0.");

		final int n = A.numRows();
		final BigInteger p = c_A.getGroup().getP();

		// Algorithm
		final GroupVector<ZqElement, ZqGroup> a_0 = randomService.genRandomVector(q, n);
		final GroupVector<ZqElement, ZqGroup> b_m = randomService.genRandomVector(q, n);
		final ZqElement r_0 = ZqElement.create(randomService.genRandomInteger(q), zqGroup);
		final ZqElement s_m = ZqElement.create(randomService.genRandomInteger(q), zqGroup);
		final GqElement c_A_0 = getCommitment(a_0, r_0, ck);
		final GqElement c_B_m = getCommitment(b_m, s_m, ck);

		// Compute the D vector.
		final GroupMatrix<ZqElement, ZqGroup> A_prepended = A.prependColumn(a_0);
		final GroupMatrix<ZqElement, ZqGroup> B_appended = B.appendColumn(b_m);

		final GroupVector<ZqElement, ZqGroup> d = computeDVector(A_prepended, B_appended, y);

		// Compute t and c_d.
		final List<ZqElement> t_mutable = new ArrayList<>(randomService.genRandomVector(q, (2 * m) + 1));
		t_mutable.set(m + 1, ZqElement.create(BigInteger.ZERO, zqGroup));
		final GroupVector<ZqElement, ZqGroup> t = GroupVector.from(t_mutable);
		final GroupVector<GqElement, GqGroup> c_d = getCommitmentVector(d, t, ck);

		// Compute x, later used to compute a', b', r', s' and t'.
		final byte[] x_bytes = hashService.recursiveHash(
				HashableBigInteger.from(p),
				HashableBigInteger.from(q),
				pk,
				ck,
				c_A_0,
				c_B_m,
				c_d,
				c_B,
				c_A
		);
		final ZqElement x = ZqElement.create(byteArrayToInteger(x_bytes), zqGroup);

		// To avoid computing multiple times the powers of x.
		final List<ZqElement> xPowers = IntStream.range(0, 2 * m + 1)
				.mapToObj(i -> x.exponentiate(BigInteger.valueOf(i)))
				.collect(Collectors.toCollection(ArrayList::new));

		// Compute vectors a' and b'.
		final GroupVector<ZqElement, ZqGroup> a_prime = IntStream.range(0, n)
				.mapToObj(j ->
						IntStream.range(0, m + 1)
								.mapToObj(i -> xPowers.get(i).multiply(A_prepended.get(j, i)))
								.reduce(zqGroup.getIdentity(), ZqElement::add))
				.collect(toGroupVector());

		final GroupVector<ZqElement, ZqGroup> b_prime = IntStream.range(0, n)
				.mapToObj(j ->
						IntStream.range(0, m + 1)
								.mapToObj(i -> xPowers.get(m - i).multiply(B_appended.get(j, i)))
								.reduce(zqGroup.getIdentity(), ZqElement::add))
				.collect(toGroupVector());

		// Compute r', s' and t'.
		final GroupVector<ZqElement, ZqGroup> r_prepended = r.prepend(r_0);
		final GroupVector<ZqElement, ZqGroup> s_appended = s.append(s_m);

		final ZqElement r_prime = IntStream.range(0, m + 1)
				.mapToObj(i -> xPowers.get(i).multiply(r_prepended.get(i)))
				.reduce(zqGroup.getIdentity(), ZqElement::add);

		final ZqElement s_prime = IntStream.range(0, m + 1)
				.mapToObj(i -> xPowers.get(m - i).multiply(s_appended.get(i)))
				.reduce(zqGroup.getIdentity(), ZqElement::add);

		final ZqElement t_prime = IntStream.range(0, 2 * m + 1)
				.mapToObj(i -> xPowers.get(i).multiply(t_mutable.get(i)))
				.reduce(zqGroup.getIdentity(), ZqElement::add);

		// Construct the ZeroArgument with all computed parameters.
		final ZeroArgument.Builder zeroArgumentBuilder = new ZeroArgument.Builder();
		zeroArgumentBuilder
				.with_c_A_0(c_A_0)
				.with_c_B_m(c_B_m)
				.with_c_d(c_d)
				.with_a_prime(a_prime)
				.with_b_prime(b_prime)
				.with_r_prime(r_prime)
				.with_s_prime(s_prime)
				.with_t_prime(t_prime);

		return zeroArgumentBuilder.build();
	}

	/**
	 * Computes the vector <b>d</b> for the GetZeroArgument algorithm. The input matrices must comply with the following:
	 * <ul>
	 *     <li>be non null</li>
	 *     <li>each matrix row must have the same number of columns</li>
	 *     <li>both matrices must have the same number of lines and columns</li>
	 *     <li>all matrix elements must be part of the same group as the value y</li>
	 * </ul>
	 *
	 * @param firstMatrix  A, the first matrix.
	 * @param secondMatrix B, the second matrix.
	 * @return the computed <b>d</b> vector.
	 */
	@VisibleForTesting
	GroupVector<ZqElement, ZqGroup> computeDVector(final GroupMatrix<ZqElement, ZqGroup> firstMatrix,
			final GroupMatrix<ZqElement, ZqGroup> secondMatrix, final ZqElement y) {

		// Null checking.
		checkNotNull(firstMatrix);
		checkNotNull(secondMatrix);
		checkNotNull(y);

		// Cross matrix dimensions checking.
		checkArgument(firstMatrix.numRows() == secondMatrix.numRows(), "The two matrices must have the same number of rows.");
		checkArgument(firstMatrix.numColumns() == secondMatrix.numColumns(), "The two matrices must have the same number of columns.");

		// Cross matrix group checking.
		checkArgument(firstMatrix.getGroup().equals(secondMatrix.getGroup()), "The elements of both matrices must be in the same group.");
		checkArgument(y.getGroup().equals(firstMatrix.getGroup()), "The value y must be in the same group as the elements of the matrices.");

		final GroupMatrix<ZqElement, ZqGroup> A = firstMatrix;
		final GroupMatrix<ZqElement, ZqGroup> B = secondMatrix;
		final int m = A.numColumns() - 1;
		final ZqGroup group = y.getGroup();

		// Computing the d vector.
		final LinkedList<ZqElement> d = new LinkedList<>();
		for (int k = 0; k <= 2 * m; k++) {
			ZqElement d_k = group.getIdentity();
			for (int i = Math.max(0, k - m); i <= m; i++) {
				final int j = (m - k) + i;
				if (j > m) {
					break;
				}
				d_k = d_k.add(starMap(A.getColumn(i), B.getColumn(j), y));
			}
			d.add(d_k);
		}

		return GroupVector.from(d);
	}

	/**
	 * Defines the bilinear map represented by the star operator &#8902; in the specification. All elements must be in the same group. The algorithm
	 * defined by the value {@code y} is the following:
	 * <p>
	 * (a<sub>0</sub>,..., a<sub>n-1</sub>) &#8902; (b<sub>0</sub>,...,b<sub>n-1</sub>) = &sum;<sub>j=0</sub><sup>n-1</sup> a<sub>j</sub> &middot;
	 * b<sub>j</sub> &middot; y<sup>j</sup>
	 *
	 * @param firstVector  a, the first vector.
	 * @param secondVector b, the second vector.
	 * @return The sum &sum;<sub>j=0</sub><sup>n-1</sup> a<sub>j</sub> &middot; b<sub>j</sub> &middot; y<sup>j</sup>
	 */
	@VisibleForTesting
	ZqElement starMap(final GroupVector<ZqElement, ZqGroup> firstVector, final GroupVector<ZqElement, ZqGroup> secondVector,
			final ZqElement y) {

		checkNotNull(firstVector);
		checkNotNull(secondVector);
		checkNotNull(y);

		final GroupVector<ZqElement, ZqGroup> a = firstVector;
		final GroupVector<ZqElement, ZqGroup> b = secondVector;

		// Cross dimensions checking.
		checkArgument(a.size() == b.size(), "The provided vectors must have the same size.");

		// Handle empty vectors.
		if (a.isEmpty()) {
			return y.getGroup().getIdentity();
		}

		// Cross group checking.
		checkArgument(a.getGroup().equals(b.getGroup()), "The elements of both vectors must be in the same group.");
		checkArgument(a.getGroup().equals(y.getGroup()), "The value y must be in the same group as the vectors elements");
		final ZqGroup group = y.getGroup();

		// StarMap computing.
		final int n = firstVector.size();
		return IntStream.range(0, n)
				.mapToObj(j -> a.get(j)
						.multiply(b.get(j))
						.multiply(y.exponentiate(BigInteger.valueOf(j + 1L))))
				.reduce(group.getIdentity(), ZqElement::add);
	}

	/**
	 * Verifies the correctness of a {@link ZeroArgument} with respect to a given {@link ZeroStatement}.
	 * <p>
	 * The statement and the argument must be non null and have compatible groups.
	 *
	 * @param argument  the statement for which the argument is to be verified.
	 * @param statement the argument to be verified.
	 * @return a {@link VerificationResult} being valid iff the argument is valid for the given statement.
	 */
	Verifiable verifyZeroArgument(final ZeroStatement statement, final ZeroArgument argument) {
		checkNotNull(statement);
		checkNotNull(argument);

		// Cross dimension checking.
		checkArgument(statement.get_m() == argument.get_m(), "The statement and argument must have the same dimension m.");

		// Cross group checking.
		checkArgument(statement.getGroup().equals(argument.getGroup()), "Statement and argument must belong to the same group.");

		final GroupVector<GqElement, GqGroup> c_A = statement.get_c_A();
		final GroupVector<GqElement, GqGroup> c_B = statement.get_c_B();
		final GqElement c_A_0 = argument.get_c_A_0();
		final GqElement c_B_m = argument.get_c_B_m();
		final GroupVector<GqElement, GqGroup> c_d = argument.get_c_d();
		final ZqElement t_prime = argument.get_t_prime();

		final int m = statement.get_m();
		final GqGroup group = statement.getGroup();
		final BigInteger p = group.getP();
		final BigInteger q = group.getQ();

		//Algorithm
		final byte[] x_bytes = hashService.recursiveHash(
				HashableBigInteger.from(p),
				HashableBigInteger.from(q),
				pk,
				ck,
				c_A_0,
				c_B_m,
				c_d,
				c_B,
				c_A
		);

		final ZqElement x = ZqElement.create(byteArrayToInteger(x_bytes), ZqGroup.sameOrderAs(group));

		final Verifiable verifCd = create(() -> BigInteger.ONE.equals(c_d.get(m + 1).getValue()),
				String.format("cd.get(m + 1).getValue() %s should equal BigInteger.ONE", c_d.get(m + 1).getValue()));

		final List<ZqElement> xPowers = IntStream.range(0, (2 * m) + 1)
				.mapToObj(i -> x.exponentiate(BigInteger.valueOf(i)))
				.toList();

		final GqElement identity = c_A.getGroup().getIdentity();

		final GroupVector<GqElement, GqGroup> c_A_prepended = c_A.prepend(argument.get_c_A_0());

		final GqElement prodCa = IntStream.range(0, m + 1)
				.mapToObj(i -> c_A_prepended.get(i).exponentiate(xPowers.get(i)))
				.reduce(identity, GqElement::multiply);

		final GroupVector<ZqElement, ZqGroup> a_prime = argument.get_a_prime();
		final ZqElement r_prime = argument.get_r_prime();

		final GqElement commA = getCommitment(a_prime, r_prime, ck);
		final Verifiable verifA = create(() -> prodCa.equals(commA), String.format("commA %s and prodCa %s are not equal", commA, prodCa));

		final GroupVector<GqElement, GqGroup> c_B_appended = c_B.append(argument.get_c_B_m());

		final GqElement prodCb = IntStream.range(0, m + 1)
				.mapToObj(i -> c_B_appended.get(m - i).exponentiate(xPowers.get(i)))
				.reduce(identity, GqElement::multiply);

		final GroupVector<ZqElement, ZqGroup> b_prime = argument.get_b_prime();
		final ZqElement s_prime = argument.get_s_prime();

		final GqElement commB = getCommitment(b_prime, s_prime, ck);
		final Verifiable verifB = create(() -> prodCb.equals(commB), String.format("prodCb %s and commB %s are not equal", prodCb, commB));

		final GqElement prodCd = IntStream.range(0, (2 * m) + 1)
				.mapToObj(i -> c_d.get(i).exponentiate(xPowers.get(i)))
				.reduce(identity, GqElement::multiply);

		final GroupVector<ZqElement, ZqGroup> prod = GroupVector.of(starMap(a_prime, b_prime, statement.get_y()));
		final GqElement commD = getCommitment(prod, t_prime, ck);
		final Verifiable verifD = create(() -> prodCd.equals(commD), String.format("prodCd %s and commD %s are not equal", prodCd, commD));

		return verifCd.and(verifA).and(verifB).and(verifD);
	}

}
