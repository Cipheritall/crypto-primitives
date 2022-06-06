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
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static ch.post.it.evoting.cryptoprimitives.math.GqElement.GqElementFactory;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.function.Predicate;

import ch.post.it.evoting.cryptoprimitives.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableBigInteger;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableString;
import ch.post.it.evoting.cryptoprimitives.math.BigIntegerOperationsService;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;

/**
 * Creates commitment keys.
 *
 * <p>This class is thread safe.</p>
 */
@SuppressWarnings("java:S117")
public class CommitmentKeyService {

	private static final String HASH_CONSTANT = "commitmentKey";

	private final HashService hashService;

	CommitmentKeyService(final HashService hashService) {
		this.hashService = checkNotNull(hashService);
	}

	/**
	 * Checks if it is possible to generate a commitment key of the requested size in the given group.
	 *
	 * @param numberOfElements the desired number of elements of the commitment key. Must be greater than zero.
	 * @param group            the group in which to generate the commitment key. Must be non null.
	 * @return true if the group is large enough to generate a key of the desired size, false otherwise.
	 */
	static boolean canGenerateKey(final int numberOfElements, final GqGroup group) {
		checkNotNull(group);

		final BigInteger requestedKeySize = BigInteger.valueOf(numberOfElements);
		final BigInteger maxKeySize = group.getQ().subtract(BigInteger.valueOf(3));
		return 0 < numberOfElements && requestedKeySize.compareTo(maxKeySize) <= 0;
	}

	/**
	 * Creates a commitment key, with the {@code numberOfCommitmentElements} specifying the commitment key's desired number of elements.
	 *
	 * @param numberOfElements ν, the desired number of elements of the commitment key. Must be strictly positive and smaller or equal to q - 3, where
	 *                         q is the order of the {@code gqGroup}.
	 * @param gqGroup          the quadratic residue group to which the commitment key belongs. Must be non null.
	 * @return the created commitment key.
	 */
	CommitmentKey getVerifiableCommitmentKey(final int numberOfElements, final GqGroup gqGroup) {
		checkNotNull(gqGroup);

		final int nu = numberOfElements;
		final BigInteger p = gqGroup.getP();
		final BigInteger q = gqGroup.getQ();
		final BigInteger g = gqGroup.getGenerator().getValue();

		checkArgument(canGenerateKey(nu, gqGroup), "The desired number of commitment elements must be in the range (0, q - 3]");

		int count = 0;
		int i = 0;

		// Using a Set to prevent duplicates.
		// A LinkedHashSet has predicable iteration order, which is the order of insertion
		final LinkedHashSet<BigInteger> v = new LinkedHashSet<>();

		final Predicate<BigInteger> validElement = w -> !w.equals(BigInteger.ZERO)
				&& !w.equals(BigInteger.ONE)
				&& !w.equals(g)
				&& !v.contains(w);

		while (count <= nu) {

			final ZqElement u = hashService.recursiveHashToZq(q, HashableBigInteger.from(q),
					HashableString.from(HASH_CONSTANT),
					HashableBigInteger.from(BigInteger.valueOf(i)),
					HashableBigInteger.from(BigInteger.valueOf(count)));

			final BigInteger w = BigIntegerOperationsService.modExponentiate(u.getValue(), BigInteger.valueOf(2), p);

			if (validElement.test(w)) {
				v.add(w);
				count++;
			}
			i++;

		}

		final List<GqElement> v_elements = v.stream()
				.map(e -> GqElementFactory.fromValue(e, gqGroup))
				.toList();

		final GqElement h = v_elements.get(0);
		final List<GqElement> g_vector = v_elements.subList(1, v_elements.size());
		return new CommitmentKey(h, g_vector);
	}
}
