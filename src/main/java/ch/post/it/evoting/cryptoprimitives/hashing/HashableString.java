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

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * Interface to be implemented by classes whose hashable form is a single {@link String}.
 */
public interface HashableString extends Hashable {

	@Override
	String toHashableForm();

	/**
	 * Utility function which creates a HashableString whose hashable form is the provided string.
	 *
	 * @param string the hashable form. Non null.
	 * @return A new HashableString whose hashable form is {@code string}
	 */
	static HashableString from(final String string) {
		checkNotNull(string);
		return () -> string;
	}
}
