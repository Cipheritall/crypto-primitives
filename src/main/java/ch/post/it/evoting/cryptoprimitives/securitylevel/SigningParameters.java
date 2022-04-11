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

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public enum SigningParameters {
	RSASSA_PSS("SHA256WITHRSAANDMGF1", "RSASSA-PSS", 3072);

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	private final String signatureAlgorithm;
	private final String keyGenerationAlgorithm;
	private final int keyLength;

	SigningParameters(final String signatureAlgorithm, final String keyGenerationAlgorithm,
			final int keyLength) {
		this.signatureAlgorithm = checkNotNull(signatureAlgorithm);
		this.keyGenerationAlgorithm = checkNotNull(keyGenerationAlgorithm);
		checkArgument(keyLength > 0);
		this.keyLength = keyLength;
	}

	public KeyPairGenerator getKeyPairGenerator() {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance(keyGenerationAlgorithm);
			generator.initialize(keyLength);
			return generator;
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(
					String.format("Requested cryptographic algorithm is not available in the environment. [Requested: %s]", keyGenerationAlgorithm),
					e);
		}
	}

	public JcaContentSignerBuilder getContentSigner() {
		return new JcaContentSignerBuilder(signatureAlgorithm);
	}

	public AlgorithmIdentifier getAlgorithmIdentifier() {
		final DefaultSignatureAlgorithmIdentifierFinder algorithmIdentifierFinder = new DefaultSignatureAlgorithmIdentifierFinder();
		return algorithmIdentifierFinder.find(signatureAlgorithm);
	}
}
