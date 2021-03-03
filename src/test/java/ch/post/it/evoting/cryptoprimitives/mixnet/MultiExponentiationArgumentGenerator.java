package ch.post.it.evoting.cryptoprimitives.mixnet;

import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;

public class MultiExponentiationArgumentGenerator {
	private final GqGroupGenerator gqGroupGenerator;
	private final ElGamalGenerator elGamalGenerator;
	private final ZqGroupGenerator zqGroupGenerator;

	public MultiExponentiationArgumentGenerator(GqGroup gqGroup) {
		this.gqGroupGenerator = new GqGroupGenerator(gqGroup);
		this.elGamalGenerator = new ElGamalGenerator(gqGroup);
		this.zqGroupGenerator = new ZqGroupGenerator(ZqGroup.sameOrderAs(gqGroup));
	}

	MultiExponentiationArgument genRandomArgument(int n, int m, int l) {
		GqElement cA0 = gqGroupGenerator.genMember();
		SameGroupVector<GqElement, GqGroup> cB = gqGroupGenerator.genRandomGqElementVector(2 * m);
		SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> E = elGamalGenerator.genRandomCiphertextVector(2 * m, l);
		SameGroupVector<ZqElement, ZqGroup> a = zqGroupGenerator.genRandomZqElementVector(n);
		ZqElement r = zqGroupGenerator.genRandomZqElementMember();
		ZqElement b = zqGroupGenerator.genRandomZqElementMember();
		ZqElement s = zqGroupGenerator.genRandomZqElementMember();
		ZqElement tau = zqGroupGenerator.genRandomZqElementMember();
		return new MultiExponentiationArgument.Builder()
				.withcA0(cA0)
				.withcBVector(cB)
				.withEVector(E)
				.withaVector(a)
				.withr(r)
				.withb(b)
				.withs(s)
				.withtau(tau)
				.build();
	}
}
