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
package ch.post.it.evoting.cryptoprimitives.zeroknowledgeproofs;

import static ch.post.it.evoting.cryptoprimitives.ConversionService.byteArrayToInteger;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableBigInteger;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableList;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableString;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

@SuppressWarnings("java:S117")
public class ExponentiationProofService {

	private final RandomService randomService;
	private final HashService hashService;

	ExponentiationProofService(final RandomService randomService, final HashService hashService) {
		this.randomService = checkNotNull(randomService);
		this.hashService = checkNotNull(hashService);
	}

	/**
	 * Computes an image of a 𝜙-function for exponentiation given a preimage and bases g<sub>0</sub>, ..., g<sub>n-1</sub>.
	 *
	 * @param preimage x ∈ Z<sub>q</sub>. Not null.
	 * @param bases    (g<sub>0</sub>, ..., g<sub>n-1</sub>) ∈ G<sub>q</sub><sup>n</sup>. Not null and not empty.
	 * @throws NullPointerException if any of the parameters are null
	 * @throws IllegalArgumentException if
	 * <ul>
	 *     <li>the bases are empty</li>
	 *     <li>the preimage does not have the same group order as the bases</li>
	 * </ul>
	 * @return an image (y<sub>0</sub>, ..., y<sub>n-1</sub>) ∈ G<sub>q</sub><sup>n</sup>
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
	 * Generates a proof of validity for the provided exponentiations.
	 *
	 * @param bases                <b>g</b> ∈ G<sub>q</sub><sup>n</sup>. Not null and not empty.
	 * @param exponent             x ∈ Z<sub>q</sub>, a secret exponent. Not null.
	 * @param exponentiations      <b>y</b> ∈ G<sub>q</sub><sup>n</sup>. Not null and not empty.
	 * @param auxiliaryInformation i<sub>aux</sub>, auxiliary information to be used for the hash. Must be non null and not contain nulls. Can be
	 *                             empty.
	 * @throws NullPointerException if any of the parameters are null.
	 * @throws IllegalArgumentException if
	 * <ul>
	 * 	 <li>the bases and the exponentiations do not have the same group</li>
	 * 	 <li>the bases and the exponentiations do not have the same size</li>
	 * 	 <li>the exponent does not have the same group order as the exponentiations</li>
	 * </ul>
	 * @return an exponentiation proof
	 */
	ExponentiationProof genExponentiationProof(final GroupVector<GqElement, GqGroup> bases, final ZqElement exponent,
			final GroupVector<GqElement, GqGroup> exponentiations, final List<String> auxiliaryInformation) {
		checkNotNull(bases);
		checkNotNull(exponent);
		checkNotNull(exponentiations);
		checkNotNull(auxiliaryInformation);

		checkArgument(auxiliaryInformation.stream().allMatch(Objects::nonNull), "The auxiliary information must not contain null objects.");

		final ImmutableList<String> i_aux = ImmutableList.copyOf(auxiliaryInformation);
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

		final BigInteger p = g.getGroup().getP();
		final BigInteger q = g.getGroup().getQ();

		// Operations.
		final BigInteger bValue = randomService.genRandomInteger(q);
		final ZqElement b = ZqElement.create(bValue, zqGroup);
		final GroupVector<GqElement, GqGroup> c = computePhiExponentiation(b, g);
		final ImmutableList<Hashable> f = ImmutableList.of(HashableBigInteger.from(p), HashableBigInteger.from(q), g);
		final HashableList h_aux = Stream.concat(Stream.of("ExponentiationProof"), i_aux.stream())
				.map(HashableString::from)
				.collect(Collectors.collectingAndThen(ImmutableList.toImmutableList(), HashableList::from));
		final BigInteger eValue = byteArrayToInteger(hashService.recursiveHash(HashableList.from(f), y, c, h_aux));
		final ZqElement e = ZqElement.create(eValue, zqGroup);
		final ZqElement z = b.add(e.multiply(x));

		return new ExponentiationProof(e, z);
	}
}
