/*
 * Copyright 2022 Post CH Ltd
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
package ch.post.it.evoting.cryptoprimitives.zeroknowledgeproofs;

import static ch.post.it.evoting.cryptoprimitives.test.tools.generator.GroupVectorElementGenerator.generateElementList;

import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;

public class DecryptionProofGenerator {

	private final ZqGroupGenerator generator;
	private final ZqGroup group;

	public DecryptionProofGenerator(ZqGroup group) {
		this.group = group;
		this.generator = new ZqGroupGenerator(group);
	}

	public DecryptionProof genDecryptionProof(int messageSize) {
		ZqElement e = generator.genRandomZqElementMember();
		GroupVector<ZqElement, ZqGroup> z = generator.genRandomZqElementVector(messageSize);
		return new DecryptionProof(e, z);
	}

	public GroupVector<DecryptionProof, ZqGroup> genDecryptionProofVector(int numMessages, int messageSize) {
		return GroupVector.from(generateElementList(numMessages,
				() -> new DecryptionProofGenerator(group).genDecryptionProof(messageSize)));
	}
}
