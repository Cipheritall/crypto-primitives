/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.math.BigIntegerOperations;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;

public class CommitmentService {

	/**
	 * <p>Computes a commitment to the given elements with the given commitment key.
	 * The commitment key must be at least as long as the number of elements to be committed.</p>
	 *
	 * @param elements 		a, the elements to be committed (a<sub>0</sub>, ..., a<sub>l</sub>)
	 * @param randomElement r, the random value
	 * @param commitmentKey	<b>ck</b>, a commitment key (h, g<sub>1</sub>, ..., g<sub>k</sub>)
	 * @return	the commitment to the provided elements as a {@link GqElement}
	 */
	GqElement getCommitment(final List<ZqElement> elements, final ZqElement randomElement, final CommitmentKey commitmentKey) {
		checkNotNull(elements);
		checkNotNull(randomElement);
		checkNotNull(commitmentKey);

		checkArgument(elements.stream().allMatch(Objects::nonNull), "Elements to be committed to cannot be null");
		ImmutableList<ZqElement> elementsCopy = ImmutableList.copyOf(elements);
		checkArgument(!elementsCopy.isEmpty(), "There must be at least one element to commit to");
		checkArgument(elementsCopy.stream().map(ZqElement::getGroup).allMatch(elementsCopy.get(0).getGroup()::equals),
				"All elements must belong to the same group");

		// by construction, commitmentKey.size() > 1
		checkArgument(elementsCopy.get(0).getGroup().equals(randomElement.getGroup()),
				"The random value must belong to the same group as the commitment elements");
		checkArgument(randomElement.getGroup().getQ().equals(commitmentKey.getGroup().getQ()),
				"The commitment key must have the same order (q) as the elements to be committed to and the random value");
		int l = elementsCopy.size();
		int k = commitmentKey.size();
		checkArgument(k >= l, "The commitment key must be equal to or longer than the list of elements to commit to");

		List<BigInteger> commitmentKeyValues =
				Stream.concat(Stream.of(commitmentKey.getH()), commitmentKey.getGElements().stream())
						.map(GroupElement::getValue)
						.collect(Collectors.toList());
		GqGroup group = commitmentKey.getGroup();
		BigInteger p = group.getP();

		List<BigInteger> commitmentValues =
				Stream.concat(Stream.of(randomElement), elementsCopy.stream())
						.map(GroupElement::getValue)
						.collect(Collectors.toList());

		BigInteger c;
		if (l == k) {
			c = BigIntegerOperations.multiModExp(commitmentKeyValues, commitmentValues, p);
		} else {
			commitmentValues.addAll(Collections.nCopies(k - l, BigInteger.ZERO));
			c = BigIntegerOperations.multiModExp(commitmentKeyValues, commitmentValues, p);
		}
		return GqElement.create(c, group);
	}
}
