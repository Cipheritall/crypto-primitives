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

import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Deque;
import java.util.LinkedList;

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

/**
 * Represents a successful verification.
 * <p>
 * This class is immutable.
 */
class VerificationSuccess implements VerificationResult {

	static final VerificationSuccess INSTANCE = new VerificationSuccess();

	private VerificationSuccess() {
		//Intentionally left blank
	}

	@Override
	public boolean isVerified() {
		return true;
	}

	@Override
	public Deque<String> getErrorMessages() {
		throw new UnsupportedOperationException();
	}
}

/**
 * Represents a verification failure. Contains a collection of error messages.
 * <p>
 * This class is immutable.
 */
class VerificationFailure implements VerificationResult {

	private final Deque<String> errorMessages = new LinkedList<>();

	private VerificationFailure(final LinkedList<String> errorMessages) {
		this.errorMessages.addAll(errorMessages);
	}

	/**
	 * Constructs a VerificationFailure with the given {@code initialErrorMessage}.
	 *
	 * @param initialErrorMessage the error message describing the failure. Not null.
	 */
	VerificationFailure(final String initialErrorMessage) {
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
	VerificationFailure addErrorMessage(final String errorMessage) {
		checkNotNull(errorMessage);

		final LinkedList<String> copy = new LinkedList<>(errorMessages);
		copy.push(errorMessage);

		return new VerificationFailure(copy);
	}
}

