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

import ch.post.it.evoting.cryptoprimitives.internal.hashing.HashService;

/**
 * Represents an object which can by hashed by the recursive hash algorithm {@link HashService#recursiveHash(Hashable...)}. This interface must NOT be
 * implemented directly. Instead classes should implement one of the sub-interfaces representing the particular hashable type. The collection of
 * sub-interfaces represent the types supported by the recursive hash, which is akin to a union type. These sub-interfaces map one to one to a Java
 * type. The supported types by the recursive hash and their respective Hashable form are:
 * <ul>
 *     <li>{@code byte[]}, see {@link HashableByteArray}</li>
 *     <li>{@code String}, see {@link HashableString}</li>
 *     <li>{@code BigInteger}, see {@link HashableBigInteger}</li>
 *     <li>{@code List<Hashable>}, see {@link HashableList}</li>
 * </ul>
 */
public interface Hashable {

	/**
	 * Converts a Hashable type object to its concrete type, which can be hashed using the recursive hash. See the class docstring for the compatible
	 * return types.
	 *
	 * @return the hashable form of the object. Should not be null.
	 * @see HashService#recursiveHash(Hashable...)
	 */
	Object toHashableForm();

}
