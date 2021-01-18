package ch.post.it.evoting.cryptoprimitives.test.tools.generator;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientKeyPair;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientMessage;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;

public class ElGamalTestDataGenerator {

	private static final RandomService randomService = new RandomService();

	private static List<GqElement> genRandomMessageElements(GqGroupMemberGenerator groupGenerator, int size){
		return Stream.generate(groupGenerator::genMember).limit(size).collect(Collectors.toList());
	}

	private static ElGamalMultiRecipientMessage genRandomMessage(GqGroupMemberGenerator groupGenerator, int size){
		return new ElGamalMultiRecipientMessage(genRandomMessageElements(groupGenerator, size));
	}

	public static ElGamalMultiRecipientPublicKey genRandomPublicKey(GqGroup group, int size) {
		return ElGamalMultiRecipientKeyPair.genKeyPair(group, size, randomService).getPublicKey();
	}

	public static ElGamalMultiRecipientCiphertext genRandomCiphertext(GqGroup group, int size){
		GqGroupMemberGenerator groupGenerator = new GqGroupMemberGenerator(group);
		ElGamalMultiRecipientMessage randomMessage = genRandomMessage(groupGenerator, size);
		ZqElement randomExponent = randomService.genRandomExponent(ZqGroup.sameOrderAs(group));
		return ElGamalMultiRecipientCiphertext.getCiphertext(randomMessage, randomExponent, genRandomPublicKey(group, size));
	}

	/**
	 * Generate a random list of ciphertexts encrypted with the same publicKey.
	 */
	public static List<ElGamalMultiRecipientCiphertext> genRandomCiphertexts(
			GqGroup group,
			ElGamalMultiRecipientPublicKey publicKey,
			int numElements,
			int numCiphertexts) {
		GqGroupMemberGenerator groupGenerator = new GqGroupMemberGenerator(group);
		ElGamalMultiRecipientMessage randomMessage = genRandomMessage(groupGenerator, numElements);
		ZqElement randomExponent = randomService.genRandomExponent(ZqGroup.sameOrderAs(group));
		return Stream.generate(() -> ElGamalMultiRecipientCiphertext.getCiphertext(randomMessage, randomExponent, publicKey))
				.limit(numCiphertexts).collect(Collectors.toList());
	}


}
