package ch.post.it.evoting.cryptoprimitives.mixnet;

import static java.util.stream.Collectors.toList;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.JsonData;

class Context {

	private final JsonData context;
	private final GqGroup gqGroup;

	Context(final JsonData contextData) {
		final BigInteger p = contextData.get("p", BigInteger.class);
		final BigInteger q = contextData.get("q", BigInteger.class);
		final BigInteger g = contextData.get("g", BigInteger.class);

		this.gqGroup = new GqGroup(p, q, g);
		this.context = contextData;
	}

	GqGroup getGqGroup() {
		return gqGroup;
	}

	ElGamalMultiRecipientPublicKey parsePublicKey() {
		final BigInteger[] pkValues = context.get("pk", BigInteger[].class);
		final List<GqElement> keyElements = Arrays.stream(pkValues)
				.map(bi -> GqElement.create(bi, gqGroup))
				.collect(toList());

		return new ElGamalMultiRecipientPublicKey(keyElements);
	}

	CommitmentKey parseCommitmentKey() {
		final BigInteger hValue = context.getJsonData("ck").get("h", BigInteger.class);
		final BigInteger[] gValues = context.getJsonData("ck").get("g", BigInteger[].class);
		final GqElement h = GqElement.create(hValue, gqGroup);
		final List<GqElement> gElements = Arrays.stream(gValues)
				.map(bi -> GqElement.create(bi, gqGroup))
				.collect(toList());

		return new CommitmentKey(h, gElements);
	}

}