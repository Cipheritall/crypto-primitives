package ch.post.it.evoting.cryptoprimitives.test.tools;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.GroupVectorElement;
import ch.post.it.evoting.cryptoprimitives.Hashable;
import ch.post.it.evoting.cryptoprimitives.HashableList;
import ch.post.it.evoting.cryptoprimitives.test.tools.math.TestGroup;

public class TestSizedElement implements GroupVectorElement<TestGroup>, HashableList {

	private final int size;
	private final TestGroup group;

	public TestSizedElement(TestGroup group, int size) {
		this.group = group;
		this.size = size;
	}

	@Override
	public TestGroup getGroup() {
		return group;
	}

	@Override
	public int size() {
		return size;
	}

	@Override
	public ImmutableList<? extends Hashable> toHashableForm() {
		throw new UnsupportedOperationException();
	}
}