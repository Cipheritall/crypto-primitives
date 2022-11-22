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

/**
 * Information about the identity of the authority generating keys, including:
 * <ul>
 * <li>common name, CN</li>
 * <li>country, C</li>
 * <li>state, ST</li>
 * <li>locality, L</li>
 * <li>organisation, O</li>
 * </ul>
 */
public class AuthorityInformation {

	private final String commonName;
	private final String country;
	private final String state;
	private final String locality;
	private final String organisation;

	private AuthorityInformation(final String commonName,
			final String country,
			final String state,
			final String locality,
			final String organisation) {
		this.commonName = commonName;
		this.country = country;
		this.state = state;
		this.locality = locality;
		this.organisation = organisation;
	}

	public String getCommonName() {
		return commonName;
	}

	public String getCountry() {
		return country;
	}

	public String getState() {
		return state;
	}

	public String getLocality() {
		return locality;
	}

	public String getOrganisation() {
		return organisation;
	}

	public static Builder builder() {
		return new Builder();
	}

	public static class Builder {
		private String commonName;
		private String country;
		private String state;
		private String locality;
		private String organisation;

		public Builder setCommonName(final String commonName) {
			this.commonName = commonName;
			return this;
		}

		public Builder setCountry(final String country) {
			this.country = country;
			return this;
		}

		public Builder setState(final String state) {
			this.state = state;
			return this;
		}

		public Builder setLocality(final String locality) {
			this.locality = locality;
			return this;
		}

		public Builder setOrganisation(final String organisation) {
			this.organisation = organisation;
			return this;
		}

		public AuthorityInformation build() {
			checkNotNull(commonName);
			checkNotNull(country);
			checkNotNull(state);
			checkNotNull(locality);
			checkNotNull(organisation);

			return new AuthorityInformation(commonName, country, state, locality, organisation);
		}
	}
}
