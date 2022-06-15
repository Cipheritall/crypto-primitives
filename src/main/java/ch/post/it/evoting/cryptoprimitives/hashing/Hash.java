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

package ch.post.it.evoting.cryptoprimitives.hashing;

import java.math.BigInteger;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;

public interface Hash {

	/**
	 * Computes the hash of multiple (potentially) recursive inputs.
	 *
	 * @param values the objects to be hashed.
	 * @return the hash of the input.
	 *
	 * <p> NOTE:
	 * <ul>
	 * 	<li>If the input object(s) are modified during the calculation of the hash, the output is undefined.</li>
	 * 	<li>It is the caller's responsibility to make sure that the input is not infinite (for example if it contains self-references).</li>
	 * </ul>
	 * @throws IllegalStateException if the creation of the underlying message digest failed.
	 */
	byte[] recursiveHash(Hashable... values);

	/**
	 * Hashes and squares a BigInteger to return a GqElement.
	 *
	 * @param x     The BigInteger to be hashed. Must be non-null.
	 * @param group The group to which the returned GqElement has to belong. Must be non-null.
	 * @return the squared hash of x as GqElement.
	 * @throws NullPointerException     if any argument is null
	 * @throws IllegalArgumentException if the bit length of the group's q is smaller than the hash length in bits
	 */
	GqElement hashAndSquare(BigInteger x, GqGroup group);

	/**
	 * Computes the hash in Z<sub>q</sub> of multiple (potentially) recursive inputs.
	 *
	 * @param exclusiveUpperBound the exlusive upper bound for the hash to be returned. Must be strictly positive.
	 * @param values              the objects to be hashed. Must be non-null.
	 * @return the result of the hashing as a {@link ZqElement} smaller than q
	 * @throws NullPointerException     if any of the arguments is null
	 * @throws IllegalArgumentException if
	 *                                  <ul>
	 *                                      <li>values contain null elements</li>
	 *                                      <li>values are empty</li>
	 *                                      <li>the requested bit length is smaller than 512</li>
	 *                                  </ul>
	 */
	ZqElement recursiveHashToZq(BigInteger exclusiveUpperBound, Hashable... values);
}
