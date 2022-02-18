/*
 *
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
 *
 */
package ch.post.it.evoting.cryptoprimitives.utils;

import java.util.function.Function;
import java.util.stream.Stream;

/**
 * Common used validations utilities.
 */
public class Validations {

	private Validations() {
		//Intentionally left blank
	}

	/**
	 * Validates that a property holds for all elements of a stream.
	 *
	 * @param <T>      the type of elements of the stream.
	 * @param stream   the elements to check.
	 * @param property the property to check all elements against.
	 * @return true if the vector is empty or all elements are equal under this property. False otherwise.
	 */
	public static <T> boolean allEqual(final Stream<T> stream, final Function<? super T, ?> property) {
		return stream.map(property).distinct().count() <= 1;
	}
}
