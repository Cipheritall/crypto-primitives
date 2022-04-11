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

/**
 * Provides functionality to retrieve the security level from an environment variable
 */
public class SecurityLevelConfig {

	private SecurityLevelConfig() {
		throw new UnsupportedOperationException("SecurityLevelConfig should not be instantiated");
	}

	/**
	 * Gets the system security level provided by the environment variable SECURITY_LEVEL. If SECURITY_LEVEL is not set, {@link SecurityLevel#DEFAULT}
	 * is used.
	 *
	 * @return a {@link SecurityLevel}
	 */
	public static SecurityLevel getSystemSecurityLevel() {
		final String securityLevelValue = System.getenv("SECURITY_LEVEL");
		if (securityLevelValue == null) {
			return SecurityLevel.DEFAULT;
		}
		return SecurityLevel.valueOf(securityLevelValue);
	}
}
