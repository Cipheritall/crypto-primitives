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

import static com.google.common.base.Preconditions.checkNotNull;
import static java.util.Date.from;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.util.function.BiFunction;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;

import ch.post.it.evoting.cryptoprimitives.internal.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.internal.signing.CertificateInfo;
import ch.post.it.evoting.cryptoprimitives.math.Random;
import ch.post.it.evoting.cryptoprimitives.securitylevel.SecurityLevel;
import ch.post.it.evoting.cryptoprimitives.internal.securitylevel.SigningParameters;

class GetCertificate implements BiFunction<KeyPair, CertificateInfo, X509Certificate> {

	private static final int SERIAL_LENGTH = 256;

	private final RandomService random;
	private final SigningParameters  signingParameters;

	GetCertificate(RandomService random, SecurityLevel securityLevel) {
		this.random = checkNotNull(random);
		checkNotNull(securityLevel);
		this.signingParameters = securityLevel.getSigningParameters();
	}

	@Override
	public X509Certificate apply(final KeyPair keyPair, final CertificateInfo info) {
		try {
			final X509v3CertificateBuilder certificateBuilder = createCertificateBuilder(keyPair.getPublic(), info);

			final ContentSigner signer = signingParameters.getContentSigner().build(keyPair.getPrivate());
			final X509CertificateHolder holder = certificateBuilder.build(signer);

			final JcaX509CertificateConverter converter = new JcaX509CertificateConverter();

			return converter.getCertificate(holder);

		} catch (OperatorCreationException | CertificateException e) {
			throw new IllegalStateException("There is a problem generating the certificate.", e);
		}
	}

	private X509v3CertificateBuilder createCertificateBuilder(final PublicKey publicKey, final CertificateInfo info) {
		final BigInteger serial = new BigInteger(random.randomBytes(SERIAL_LENGTH));

		final X500Name subject = new X500NameBuilder(BCStyle.INSTANCE)
				.addRDN(BCStyle.CN, info.getAuthorityInformation().getCommonName())
				.addRDN(BCStyle.C, info.getAuthorityInformation().getCountry())
				.addRDN(BCStyle.O, info.getAuthorityInformation().getOrganisation())
				.addRDN(BCStyle.L, info.getAuthorityInformation().getLocality())
				.addRDN(BCStyle.ST, info.getAuthorityInformation().getState())
				.build();

		final JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
				subject,
				serial,
				from(info.getValidFrom().atStartOfDay(ZoneId.of("Europe/Zurich")).toInstant()),
				from(info.getValidUntil().atStartOfDay(ZoneId.of("Europe/Zurich")).toInstant()),
				subject,
				publicKey);

		try {
			builder.addExtension(Extension.keyUsage, true, info.getUsage());
		} catch (CertIOException e) {
			throw new IllegalStateException("Badly configured extension.", e);
		}

		return builder;
	}
}
