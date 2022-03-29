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

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x509.KeyUsage;

import com.google.common.annotations.VisibleForTesting;

import ch.post.it.evoting.cryptoprimitives.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.securitylevel.SecurityLevel;
import ch.post.it.evoting.cryptoprimitives.securitylevel.SecurityLevelConfig;

/**
 * Implements the GenKeysAndCert algorithm.
 */
public class GenKeysAndCertService implements DigitalSignatures {

	private final GenKeyPair genKeyPair;
	private final GetCertificate getCertificate;
	private final AuthorityInformation authorityInformation;

	/**
	 * @param random               generator to be used. Must not be null.
	 * @param authorityInformation used to generate the certificate. Must not be null.
	 * @throws NullPointerException if any argument is null
	 */

	public GenKeysAndCertService(final RandomService random, AuthorityInformation authorityInformation) {
		this(random, authorityInformation, SecurityLevelConfig.getSystemSecurityLevel());
	}

	private GenKeysAndCertService(final RandomService random, AuthorityInformation authorityInformation, SecurityLevel securityLevel) {
		this(new GenKeyPair(securityLevel), new GetCertificate(random, securityLevel), authorityInformation);
	}

	@VisibleForTesting
	GenKeysAndCertService(GenKeyPair genKeyPair, GetCertificate getCertificate, AuthorityInformation authorityInformation) {
		this.genKeyPair = checkNotNull(genKeyPair);
		this.getCertificate = checkNotNull(getCertificate);
		this.authorityInformation = checkNotNull(authorityInformation);
	}

	@Override
	public GenKeysAndCertOutput genKeysAndCert(final Date validFrom, final Date validUntil) throws IllegalArgumentException {
		checkNotNull(validFrom);
		checkNotNull(validUntil);
		checkArgument(validUntil.after(validFrom), "Date validFrom is after validUntil");

		final KeyPair keyPair = genKeyPair.get();

		final CertificateInfo info = new CertificateInfo(authorityInformation);
		info.setValidFrom(validFrom);
		info.setValidUntil(validUntil);
		final KeyUsage usage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature);
		info.setUsage(usage);

		final X509Certificate certificate = getCertificate.apply(keyPair, info);

		return new GenKeysAndCertOutput(keyPair.getPrivate(), certificate);
	}

}
