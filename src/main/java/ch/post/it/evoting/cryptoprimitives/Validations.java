/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives;

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
	 * Validate that a property holds for all elements of a stream.
	 *
	 * @param <T> the type of elements of the stream.
	 * @param stream the elements to check.
	 * @param property the property to check all elements against.
	 * @return true if the vector is empty or all elements are equal under this property. False otherwise.
	 */
	public static <T> boolean allEqual(Stream<T> stream, Function<? super T, ?> property) {
		return stream.map(property).distinct().count() <= 1;
	}
}
