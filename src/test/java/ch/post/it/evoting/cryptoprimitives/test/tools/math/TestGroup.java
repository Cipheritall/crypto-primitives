/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.test.tools.math;

import java.math.BigInteger;

import ch.post.it.evoting.cryptoprimitives.math.GroupElement;
import ch.post.it.evoting.cryptoprimitives.math.MathematicalGroup;

public class TestGroup implements MathematicalGroup<TestGroup> {
	@Override
	public boolean isGroupMember(BigInteger value) {
		throw new UnsupportedOperationException();
	}

	@Override
	public GroupElement<TestGroup> getIdentity() {
		throw new UnsupportedOperationException();
	}

	@Override
	public BigInteger getQ() {
		throw new UnsupportedOperationException();
	}
}

