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

package ch.post.it.evoting.cryptoprimitives.internal.utils;

import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Deque;
import java.util.LinkedList;

import ch.post.it.evoting.cryptoprimitives.utils.VerificationResult;

/**
 * Represents a verification failure. Contains a collection of error messages.
 * <p>
 * This class is immutable.
 */
public final class VerificationFailure implements VerificationResult {

	private final Deque<String> errorMessages = new LinkedList<>();

	private VerificationFailure(final LinkedList<String> errorMessages) {
		this.errorMessages.addAll(errorMessages);
	}

	/**
	 * Constructs a VerificationFailure with the given {@code initialErrorMessage}.
	 *
	 * @param initialErrorMessage the error message describing the failure. Not null.
	 */
	public VerificationFailure(final String initialErrorMessage) {
		checkNotNull(initialErrorMessage);
		this.errorMessages.push(initialErrorMessage);
	}

	@Override
	public boolean isVerified() {
		return false;
	}

	@Override
	public Deque<String> getErrorMessages() {
		return new LinkedList<>(this.errorMessages);
	}

	/**
	 * Creates a new VerificationFailure with an additional error message.
	 *
	 * @param errorMessage the error message to add. Must be not null.
	 * @return a new VerificationResult containing the newly added {@code errorMessage}.
	 */
	public VerificationFailure addErrorMessage(final String errorMessage) {
		checkNotNull(errorMessage);

		final LinkedList<String> copy = new LinkedList<>(errorMessages);
		copy.push(errorMessage);

		return new VerificationFailure(copy);
	}
}
