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

import com.google.common.collect.ImmutableList;

/**
 * Interface to be implemented by classes whose hashable form is an {@link ImmutableList} of {@link Hashable} objects.
 */
public interface HashableList extends Hashable {

	@Override
	ImmutableList<? extends Hashable> toHashableForm();

	static HashableList from(final ImmutableList<Hashable> list) {
		return () -> list;
	}
}