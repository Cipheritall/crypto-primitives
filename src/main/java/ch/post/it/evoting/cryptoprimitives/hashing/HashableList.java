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
package ch.post.it.evoting.cryptoprimitives.hashing;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import com.google.common.collect.ImmutableList;

/**
 * Interface to be implemented by classes whose hashable form is an immutable list of {@link Hashable} objects.
 */
public interface HashableList extends Hashable {

	@Override
	ImmutableList<? extends Hashable> toHashableForm();

	/**
	 * Creates a HashableList whose hashable form is the provided list.
	 *
	 * @param list the hashable form. Non null.
	 * @return A new HashableList whose hashable form is {@code list}
	 */
	static HashableList from(final List<? extends Hashable> list) {
		checkNotNull(list);

		// The copy has to be done outside of the lambda, otherwise it will be made only when #toHashableForm is called.
		final ImmutableList<? extends Hashable> immutableList = ImmutableList.copyOf(list);
		checkArgument(!immutableList.isEmpty(), "The list must not be empty.");

		return () -> immutableList;
	}

	/**
	 * Creates a HashableList whose hashable form is an ImmutableList containing the provided elements.
	 *
	 * @param elements the hashable elements to construct a HashableList from. Non null and must not contain nulls.
	 * @param <E> the type of the elements
	 * @return a HashableList with the provided elements
	 */
	@SafeVarargs
	static <E extends Hashable> HashableList of(final E... elements) {
		checkNotNull(elements);
		checkArgument(Arrays.stream(elements).allMatch(Objects::nonNull), "Elements must not contain nulls");

		return from(Arrays.asList(elements));
	}
}
