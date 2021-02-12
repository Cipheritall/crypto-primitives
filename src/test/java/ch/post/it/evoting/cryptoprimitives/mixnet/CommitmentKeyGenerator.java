/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static com.google.common.base.Preconditions.checkNotNull;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;

public class CommitmentKeyGenerator {

	private final GqGroupGenerator generator;

	CommitmentKeyGenerator(GqGroup group) {
		checkNotNull(group);
		this.generator = new GqGroupGenerator(group);

	}

	/**
	 * Generate a random commitment key in the given group and of given size.
	 * @param k     the number of g elements of the key.
	 * @return a new commitment key of length k + 1.
	 */
	CommitmentKey genCommitmentKey(int k) {
		GqElement h = generator.genNonIdentityNonGeneratorMember();
		List<GqElement> gList = Stream.generate(generator::genNonIdentityNonGeneratorMember).limit(k).collect(Collectors.toList());
		return new CommitmentKey(h, gList);
	}
}
