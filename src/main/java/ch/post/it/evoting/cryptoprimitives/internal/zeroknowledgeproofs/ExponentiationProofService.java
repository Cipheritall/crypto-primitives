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
package ch.post.it.evoting.cryptoprimitives.internal.zeroknowledgeproofs;

import static ch.post.it.evoting.cryptoprimitives.internal.utils.ConversionsInternal.byteArrayToInteger;
import static ch.post.it.evoting.cryptoprimitives.math.GroupVector.toGroupVector;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;
import java.util.stream.IntStream;

import ch.post.it.evoting.cryptoprimitives.hashing.HashableBigInteger;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableList;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableString;
import ch.post.it.evoting.cryptoprimitives.internal.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.internal.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.zeroknowledgeproofs.ExponentiationProof;
import ch.post.it.evoting.cryptoprimitives.zeroknowledgeproofs.ZeroKnowledgeProof;

/**
 * <p>This class is thread safe.</p>
 */
@SuppressWarnings("java:S117")
public class ExponentiationProofService {

	private static final String EXPONENTIATION_PROOF = "ExponentiationProof";

	private final RandomService randomService;
	private final HashService hashService;

	public ExponentiationProofService(final RandomService randomService, final HashService hashService) {
		this.randomService = checkNotNull(randomService);
		this.hashService = checkNotNull(hashService);
	}

	/**
	 * Computes an image of a phi-function for exponentiation given a preimage and bases g<sub>0</sub>, ..., g<sub>n-1</sub>.
	 *
	 * @param preimage x ∈ Z<sub>q</sub>. Not null.
	 * @param bases    (g<sub>0</sub>, ..., g<sub>n-1</sub>) ∈ G<sub>q</sub><sup>n</sup>. Not null and not empty.
	 * @return an image (y<sub>0</sub>, ..., y<sub>n-1</sub>) ∈ G<sub>q</sub><sup>n</sup>
	 * @throws NullPointerException     if any of the parameters are null
	 * @throws IllegalArgumentException if
	 *                                  <ul>
	 *                                      <li>the bases are empty</li>
	 *                                      <li>the preimage does not have the same group order as the bases</li>
	 *                                  </ul>
	 */
	static GroupVector<GqElement, GqGroup> computePhiExponentiation(final ZqElement preimage, final GroupVector<GqElement, GqGroup> bases) {
		checkNotNull(preimage);
		checkNotNull(bases);

		checkArgument(!bases.isEmpty(), "The vector of bases must contain at least 1 element.");
		checkArgument(preimage.getGroup().hasSameOrderAs(bases.getGroup()), "The preimage and the bases must have the same group order.");

		final ZqElement x = preimage;
		final GroupVector<GqElement, GqGroup> g = bases;

		return g.stream().map(g_i -> g_i.exponentiate(x)).collect(GroupVector.toGroupVector());
	}

	/**
	 * @see ZeroKnowledgeProof#genExponentiationProof(GroupVector, ZqElement, GroupVector, List)
	 */
	public ExponentiationProof genExponentiationProof(final GroupVector<GqElement, GqGroup> bases, final ZqElement exponent,
			final GroupVector<GqElement, GqGroup> exponentiations, final List<String> auxiliaryInformation) {
		checkNotNull(bases);
		checkNotNull(exponent);
		checkNotNull(exponentiations);
		checkNotNull(auxiliaryInformation);

		checkArgument(auxiliaryInformation.stream().allMatch(Objects::nonNull), "The auxiliary information must not contain null objects.");

		final List<String> i_aux = List.copyOf(auxiliaryInformation);
		final GroupVector<GqElement, GqGroup> g = bases;
		final ZqElement x = exponent;
		final GroupVector<GqElement, GqGroup> y = exponentiations;
		final ZqGroup zqGroup = x.getGroup();

		// Cross-dimension checks
		checkArgument(!g.isEmpty(), "The bases must contain at least 1 element.");
		checkArgument(g.size() == y.size(), "Bases and exponentiations must have the same size.");

		// Cross-group checks
		checkArgument(g.getGroup().equals(y.getGroup()), "Bases and exponentiations must have the same group.");
		checkArgument(x.getGroup().hasSameOrderAs(y.getGroup()),
				"The exponent and the exponentiations must have the same group order.");

		checkArgument(y.equals(computePhiExponentiation(x, g)),
				"The exponentiations must correspond to the exponent's and bases' phi exponentiation.");

		// Context
		final BigInteger p = g.getGroup().getP();
		final BigInteger q = g.getGroup().getQ();
		checkArgument(hashService.getHashLength() * Byte.SIZE < q.bitLength(),
				"The hash service's bit length must be smaller than the bit length of q.");

		// Operations.
		final BigInteger bValue = randomService.genRandomInteger(q);
		final ZqElement b = ZqElement.create(bValue, zqGroup);
		final GroupVector<GqElement, GqGroup> c = computePhiExponentiation(b, g);
		final HashableList f = HashableList.of(HashableBigInteger.from(p), HashableBigInteger.from(q), g);
		final HashableList h_aux;
		if (!i_aux.isEmpty()) {
			h_aux = HashableList.of(HashableString.from(EXPONENTIATION_PROOF),
					HashableList.from(i_aux.stream()
							.map(HashableString::from)
							.toList()));
		} else {
			h_aux = HashableList.of(HashableString.from(EXPONENTIATION_PROOF));
		}
		final BigInteger eValue = byteArrayToInteger(hashService.recursiveHash(f, y, c, h_aux));
		final ZqElement e = ZqElement.create(eValue, zqGroup);
		final ZqElement z = b.add(e.multiply(x));

		return new ExponentiationProof(e, z);
	}

	/**
	 * @see ZeroKnowledgeProof#verifyExponentiation(GroupVector, GroupVector, ExponentiationProof, List)
	 */
	public boolean verifyExponentiation(final GroupVector<GqElement, GqGroup> bases, final GroupVector<GqElement, GqGroup> exponentiations,
			final ExponentiationProof proof, final List<String> auxiliaryInformation) {
		checkNotNull(bases);
		checkNotNull(exponentiations);
		checkNotNull(proof);
		checkNotNull(auxiliaryInformation);

		checkArgument(auxiliaryInformation.stream().allMatch(Objects::nonNull), "The auxiliary information must not contain null elements.");

		final List<String> i_aux = List.copyOf(auxiliaryInformation);
		final GroupVector<GqElement, GqGroup> g = bases;
		final GroupVector<GqElement, GqGroup> y = exponentiations;
		final ZqElement e = proof.get_e();
		final ZqElement z = proof.get_z();
		final int n = g.size();

		// Cross-dimension checking
		checkArgument(!g.isEmpty(), "The bases must contain at least 1 element.");
		checkArgument(g.size() == y.size(), "Bases and exponentiations must have the same size.");

		// Cross-group checking
		checkArgument(g.getGroup().equals(y.getGroup()), "Bases and exponentiations must belong to the same group.");
		checkArgument(proof.getGroup().hasSameOrderAs(bases.getGroup()), "The proof must have the same group order as the bases.");

		// Context
		final ZqGroup zqGroup = e.getGroup();
		final BigInteger p = g.getGroup().getP();
		final BigInteger q = g.getGroup().getQ();
		checkArgument(hashService.getHashLength() * Byte.SIZE < q.bitLength(),
				"The hash service's bit length must be smaller than the bit length of q.");

		// Operations
		final GroupVector<GqElement, GqGroup> x = computePhiExponentiation(z, g);
		final HashableList f = HashableList.of(HashableBigInteger.from(p), HashableBigInteger.from(q), g);
		final GroupVector<GqElement, GqGroup> c_prime = IntStream.range(0, n)
				.mapToObj(i -> x.get(i).multiply(y.get(i).exponentiate(e.negate())))
				.collect(toGroupVector());
		final HashableList h_aux;
		if (!i_aux.isEmpty()) {
			h_aux = HashableList.of(HashableString.from(EXPONENTIATION_PROOF),
					HashableList.from(i_aux.stream()
							.map(HashableString::from)
							.toList()));
		} else {
			h_aux = HashableList.of(HashableString.from(EXPONENTIATION_PROOF));
		}
		final byte[] h = hashService.recursiveHash(f, y, c_prime, h_aux);
		final BigInteger e_prime_value = byteArrayToInteger(h);
		final ZqElement e_prime = ZqElement.create(e_prime_value, zqGroup);

		return e.equals(e_prime);
	}
}
