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
package ch.post.it.evoting.cryptoprimitives;

/**
 * Represents an object that is hashable by the recursive hash algorithm. This interface must NOT be implemented directly. Instead objects should
 * implement the sub-interfaces representing the particular hashable form of a Java type.
 * <p>
 * The allowed types returned by the {@code toHashableForm} method are the following:
 * <ul>
 *     <li>byte[]</li>
 *     <li>String</li>
 *     <li>BigInteger</li>
 *     <li>List<Hashable></li>
 * </ul>
 *
 * @see ch.post.it.evoting.cryptoprimitives.HashService#recursiveHash(Hashable...)
 */
public interface Hashable {

	/**
	 * Converts an object to its hashable form. The allowed return types are defined by the recursive hash algorithm.
	 *
	 * @return the hashable form of the object.
	 * @see ch.post.it.evoting.cryptoprimitives.HashService#recursiveHash(Hashable...)
	 */
	Object toHashableForm();

}
