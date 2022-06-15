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
package ch.post.it.evoting.cryptoprimitives.signing;

import static com.google.common.base.Preconditions.checkNotNull;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Contains a private key and a self sign certificate for the matching public key.
 */
public record KeysAndCert(PrivateKey privateKey, X509Certificate certificate) {

	/**
	 * @param privateKey  - privKey, the private key which the authority will keep secret and use for signing.
	 * @param certificate - cert, the certificate which will be shared with the other authorities, so that they can verify messages signed by this
	 *                    authority.
	 * @throws NullPointerException if any argument is null
	 */
	public KeysAndCert {
		checkNotNull(privateKey);
		checkNotNull(certificate);
	}
}
