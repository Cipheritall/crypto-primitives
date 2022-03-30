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

import java.util.Date;

public interface DigitalSignatures {

	/**
	 * Generates a private key and a self-signed certificate containing the corresponding public key, with use restricted to signing, for a limited
	 * duration.
	 *
	 * @param validFrom  - validFrom, start of certificate validity. Must not be null.
	 * @param validUntil - validUntil, end of certificate validity. Must not be null.
	 * @return the private key and the associated certificate encapsulated in a {@link GenKeysAndCertOutput}.
	 * @throws NullPointerException     if any argument is null.
	 * @throws IllegalArgumentException if the dates are incoherent (validFrom after validUntil).
	 */
	GenKeysAndCertOutput genKeysAndCert(final Date validFrom, final Date validUntil) throws IllegalArgumentException;

}
