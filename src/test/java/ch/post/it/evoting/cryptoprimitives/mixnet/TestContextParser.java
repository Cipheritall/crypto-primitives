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
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static ch.post.it.evoting.cryptoprimitives.math.GqElement.GqElementFactory;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

import org.mockito.MockedStatic;
import org.mockito.Mockito;

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.securitylevel.SecurityLevel;
import ch.post.it.evoting.cryptoprimitives.securitylevel.SecurityLevelConfig;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.JsonData;

class TestContextParser {

	private final JsonData context;
	private final GqGroup gqGroup;

	TestContextParser(final JsonData contextData) {
		try (MockedStatic<SecurityLevelConfig> mockedSecurityLevel = Mockito.mockStatic(SecurityLevelConfig.class)) {
			final BigInteger p = contextData.get("p", BigInteger.class);
			final BigInteger q = contextData.get("q", BigInteger.class);
			final BigInteger g = contextData.get("g", BigInteger.class);

			switch (p.bitLength()) {
			case 3072:
				mockedSecurityLevel.when(SecurityLevelConfig::getSystemSecurityLevel).thenReturn(SecurityLevel.EXTENDED);
				break;
			case 2048:
				mockedSecurityLevel.when(SecurityLevelConfig::getSystemSecurityLevel).thenReturn(SecurityLevel.DEFAULT);
				break;
			default:
				throw new IllegalArgumentException("Unexpected bit length of p");
			}

			this.gqGroup = new GqGroup(p, q, g);
			this.context = contextData;
		}
	}

	GqGroup getGqGroup() {
		return gqGroup;
	}

	ElGamalMultiRecipientPublicKey parsePublicKey() {
		final BigInteger[] pkValues = context.get("pk", BigInteger[].class);
		final List<GqElement> keyElements = Arrays.stream(pkValues)
				.map(bi -> GqElementFactory.fromValue(bi, gqGroup))
				.toList();

		return new ElGamalMultiRecipientPublicKey(keyElements);
	}

	CommitmentKey parseCommitmentKey() {
		final BigInteger hValue = context.getJsonData("ck").get("h", BigInteger.class);
		final BigInteger[] gValues = context.getJsonData("ck").get("g", BigInteger[].class);
		final GqElement h = GqElementFactory.fromValue(hValue, gqGroup);
		final List<GqElement> gElements = Arrays.stream(gValues)
				.map(bi -> GqElementFactory.fromValue(bi, gqGroup))
				.toList();

		return new CommitmentKey(h, gElements);
	}

}
