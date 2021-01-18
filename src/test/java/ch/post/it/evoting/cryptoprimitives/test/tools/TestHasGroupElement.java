/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.test.tools;

import java.security.SecureRandom;

import ch.post.it.evoting.cryptoprimitives.HasGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.math.TestGroup;

public class TestHasGroupElement implements HasGroup<TestGroup> {
	private static final SecureRandom random = new SecureRandom();

	private final TestGroup group;

	//Create a TestHasGroupElement with a random value with the given group
	public TestHasGroupElement(TestGroup group) {
		this.group = group;
	}

	@Override
	public TestGroup getGroup() {
		return this.group;
	}
}

