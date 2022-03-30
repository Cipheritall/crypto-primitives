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

import java.util.Date;

import org.bouncycastle.asn1.x509.KeyUsage;

/**
 * Represent the "info" object of the spec.
 */
class CertificateInfo {

	private final AuthorityInformation authorityInformation;
	private Date validFrom;
	private Date validUntil;
	private KeyUsage usage;

	public CertificateInfo(final AuthorityInformation authorityInformation) {
		this.authorityInformation = checkNotNull(authorityInformation);
	}

	public AuthorityInformation getAuthorityInformation() {
		return authorityInformation;
	}

	public Date getValidFrom() {
		return validFrom;
	}

	public Date getValidUntil() {
		return validUntil;
	}

	public KeyUsage getUsage() {
		return usage;
	}

	public void setValidFrom(final Date validFrom) {
		this.validFrom = checkNotNull(validFrom);
		checkValidityDatesConsistency();
	}

	public void setValidUntil(final Date validUntil) {
		this.validUntil = checkNotNull(validUntil);
		checkValidityDatesConsistency();
	}

	public void setUsage(final KeyUsage usage) {
		this.usage = usage;
	}

	private void checkValidityDatesConsistency() {
		if (validFrom != null && validUntil != null) {
			checkArgument(validUntil.after(validFrom), "Date validFrom is after validUntil");
		}
	}
}
