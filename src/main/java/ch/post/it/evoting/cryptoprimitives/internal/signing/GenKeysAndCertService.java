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
package ch.post.it.evoting.cryptoprimitives.internal.signing;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.LocalDate;

import org.bouncycastle.asn1.x509.KeyUsage;

import ch.post.it.evoting.cryptoprimitives.internal.securitylevel.SignatureSupportingAlgorithm;
import ch.post.it.evoting.cryptoprimitives.signing.AuthorityInformation;
import ch.post.it.evoting.cryptoprimitives.signing.GenKeysAndCert;
import ch.post.it.evoting.cryptoprimitives.signing.KeysAndCert;

/**
 * Implements the GenKeysAndCert algorithm.
 */
public class GenKeysAndCertService implements GenKeysAndCert {
	private final AuthorityInformation authorityInformation;
	private final SignatureSupportingAlgorithm signatureSupportingAlgorithm;

	/**
	 * @param authorityInformation used to generate the certificate. Must not be null.
	 * @throws NullPointerException if any argument is null
	 */
	public GenKeysAndCertService(final AuthorityInformation authorityInformation, final SignatureSupportingAlgorithm signatureSupportingAlgorithm) {
		this.authorityInformation = checkNotNull(authorityInformation);
		this.signatureSupportingAlgorithm = checkNotNull(signatureSupportingAlgorithm);
	}

	@Override
	public KeysAndCert genKeysAndCert(final LocalDate validFrom, final LocalDate validUntil) throws IllegalArgumentException {
		checkNotNull(validFrom);
		checkNotNull(validUntil);
		checkArgument(validUntil.isAfter(validFrom), "Date validFrom is after validUntil");

		final KeyPair keyPair = signatureSupportingAlgorithm.genKeyPair();

		final CertificateInfo info = new CertificateInfo(authorityInformation);
		info.setValidFrom(validFrom);
		info.setValidUntil(validUntil);
		final KeyUsage usage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature);
		info.setUsage(usage);

		final X509Certificate certificate = signatureSupportingAlgorithm.getCertificate(keyPair, info);

		return new KeysAndCert(keyPair.getPrivate(), certificate);
	}
}
