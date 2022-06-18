/*
 *
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
 *
 */
package ch.post.it.evoting.cryptoprimitives.utils;

import java.util.Deque;

/**
 * Represents the result of a verification. Contains a list of errors in case of failure.
 *
 * <p>Instances of this class are immutable. </p>
 */
public interface VerificationResult {

	/**
	 * @return {@code true} iff this verification succeeded.
	 */
	boolean isVerified();

	/**
	 * Gets error messages. Only possible for failed verifications.
	 *
	 * @return a copy of the error messages list. This is analogous to a stack trace of errors. The first error message represents the highest level
	 * error.
	 */
	Deque<String> getErrorMessages();
}

