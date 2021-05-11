/*
 * Copyright 2021 Post CH Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ch.post.it.evoting.cryptoprimitives.test.tools.generator;

import static ch.post.it.evoting.cryptoprimitives.test.tools.generator.GroupVectorElementGenerator.generateElementList;
import static ch.post.it.evoting.cryptoprimitives.test.tools.generator.GroupVectorElementGenerator.generateElementMatrix;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ch.post.it.evoting.cryptoprimitives.GroupMatrix;
import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientKeyPair;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientMessage;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPrivateKey;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

public class ElGamalGenerator {

	private static final RandomService randomService = new RandomService();

	private final GqGroup group;
	private final GqGroupGenerator groupGenerator;

	public ElGamalGenerator(GqGroup group) {
		this.group = group;
		this.groupGenerator = new GqGroupGenerator(group);
	}

	private List<GqElement> genRandomMessageElements(int size) {
		return generateElementList(size, this.groupGenerator::genMember);
	}

	public ElGamalMultiRecipientMessage genRandomMessage(int size) {
		return new ElGamalMultiRecipientMessage(genRandomMessageElements(size));
	}

	public ElGamalMultiRecipientPublicKey genRandomPublicKey(int size) {
		return ElGamalMultiRecipientKeyPair.genKeyPair(group, size, randomService).getPublicKey();
	}

	public ElGamalMultiRecipientPrivateKey genRandomPrivateKey(int size) {
		return ElGamalMultiRecipientKeyPair.genKeyPair(group, size, randomService).getPrivateKey();
	}

	public ElGamalMultiRecipientCiphertext genRandomCiphertext(int ciphertextSize) {
		ElGamalMultiRecipientMessage randomMessage = genRandomMessage(ciphertextSize);
		ZqElement randomExponent = ZqElement.create(randomService.genRandomInteger(group.getQ()), ZqGroup.sameOrderAs(group));
		return ElGamalMultiRecipientCiphertext.getCiphertext(randomMessage, randomExponent, genRandomPublicKey(ciphertextSize));
	}

	public GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> genRandomCiphertextVector(int size, int ciphertextSize) {
		return GroupVector.from(generateElementList(size, () -> genRandomCiphertext(ciphertextSize)));
	}

	public GroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> genRandomCiphertextMatrix(int numRows, int numColumns, int ciphertextSize) {
		return GroupMatrix.fromRows(generateElementMatrix(numRows, numColumns, () -> genRandomCiphertext(ciphertextSize)));
	}

	public GroupVector<ElGamalMultiRecipientMessage, GqGroup> genRandomMessageVector(int size, int messageSize) {
		return GroupVector.from(generateElementList(size, () -> genRandomMessage(messageSize)));
	}

	/**
	 * Generate a random list of ciphertexts encrypted with the same publicKey.
	 */
	public List<ElGamalMultiRecipientCiphertext> genRandomCiphertexts(ElGamalMultiRecipientPublicKey publicKey, int numElements, int numCiphertexts) {
		ElGamalMultiRecipientMessage randomMessage = genRandomMessage(numElements);
		ZqElement randomExponent = ZqElement.create(randomService.genRandomInteger(group.getQ()), ZqGroup.sameOrderAs(group));

		return Stream.generate(() -> ElGamalMultiRecipientCiphertext.getCiphertext(randomMessage, randomExponent, publicKey))
				.limit(numCiphertexts).collect(Collectors.toList());
	}

	public static ElGamalMultiRecipientCiphertext encryptMessage(ElGamalMultiRecipientMessage originalMessage, ElGamalMultiRecipientKeyPair keyPair,
			ZqGroup zqGroup) {
		RandomService randomService = new RandomService();
		ZqElement exponent = ZqElement.create(randomService.genRandomInteger(zqGroup.getQ()), zqGroup);
		return ElGamalMultiRecipientCiphertext.getCiphertext(originalMessage, exponent, keyPair.getPublicKey());
	}

	public ElGamalMultiRecipientCiphertext otherCiphertext(ElGamalMultiRecipientCiphertext element) {
		return Generators.genWhile(() -> genRandomCiphertext(element.size()), element::equals);
	}
}
