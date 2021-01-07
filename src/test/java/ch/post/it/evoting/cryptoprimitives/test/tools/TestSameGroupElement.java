/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.test.tools;

import java.math.BigInteger;
import java.security.SecureRandom;

import ch.post.it.evoting.cryptoprimitives.HasGroup;
import ch.post.it.evoting.cryptoprimitives.HashableBigInteger;
import ch.post.it.evoting.cryptoprimitives.test.tools.math.TestGroup;

public class TestSameGroupElement implements HasGroup<TestGroup>, HashableBigInteger {
	private static final SecureRandom random = new SecureRandom();

	private final TestGroup group;

	//Create a TestSameGroupElement with a random value with the given group
	public TestSameGroupElement(TestGroup group) {
		this.group = group;
	}

	@Override
	public TestGroup getGroup() {
		return this.group;
	}

	@Override
	public BigInteger toHashableForm() {
		throw new UnsupportedOperationException();
	}
}

