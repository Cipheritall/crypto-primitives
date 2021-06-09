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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("A HashableList")
class HashableListTest {

	@Test
	@DisplayName("correctly makes a copy of the input list")
	void hashableListFromMakesCopy() {
		final List<Hashable> list = new ArrayList<>();
		list.add(HashableString.from("a"));

		final List<String> expected = new ArrayList<>();
		expected.add("a");

		final HashableList hashableList = HashableList.from(list);
		final List<Object> toHashableFormList = hashableList.toHashableForm().stream().map(Hashable::toHashableForm).collect(Collectors.toList());

		assertEquals(expected, toHashableFormList);

		// Modify original list.
		list.add(HashableString.from("b"));

		final List<Object> toHashableFormListAddedElement = hashableList.toHashableForm().stream().map(Hashable::toHashableForm)
				.collect(Collectors.toList());

		assertEquals(expected, toHashableFormListAddedElement);
	}

	@Test
	@DisplayName("cannot be created from an empty list")
	void hashableListFromEmptyListThrows() {
		final List<HashableString> emptyList = Collections.emptyList();
		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> HashableList.from(emptyList));
		assertEquals("The list must not be empty.", exception.getMessage());
	}

}
