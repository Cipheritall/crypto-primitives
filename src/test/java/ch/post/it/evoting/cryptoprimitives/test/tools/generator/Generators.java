/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.test.tools.generator;

import java.util.function.Predicate;
import java.util.function.Supplier;

public class Generators {
	public static <T> T genWhile(Supplier<T> producer, Predicate<T> invalid) {
		T member;
		do {
			member = producer.get();
		} while (invalid.test(member));
		return member;
	}
}
