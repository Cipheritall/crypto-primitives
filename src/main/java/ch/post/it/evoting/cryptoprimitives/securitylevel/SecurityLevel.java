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
package ch.post.it.evoting.cryptoprimitives.securitylevel;

import static ch.post.it.evoting.cryptoprimitives.internal.securitylevel.SigningParameters.RSASSA_PSS;

import ch.post.it.evoting.cryptoprimitives.internal.securitylevel.SigningParameters;

/**
 * Represents the possible security levels.
 */
public enum SecurityLevel {

	TESTING_ONLY(16, 48, RSASSA_PSS),
	DEFAULT(112, 2048, RSASSA_PSS),
	EXTENDED(128, 3072, RSASSA_PSS);

	private final int strength;
	private final int bitLength;
	private final SigningParameters signingParameters;

	SecurityLevel(final int strength, final int bitLength, final SigningParameters signingParameters) {
		this.strength = strength;
		this.bitLength = bitLength;
		this.signingParameters = signingParameters;
	}

	public int getStrength() {
		return strength;
	}

	public int getBitLength() {
		return this.bitLength;
	}

	public SigningParameters getSigningParameters() {
		return signingParameters;
	}
}
