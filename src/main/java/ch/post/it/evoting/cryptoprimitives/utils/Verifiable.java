/*
 *
 * Copyright 2021 Post CH Ltd
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

import java.util.function.BooleanSupplier;
import java.util.function.Supplier;

/**
 * Represents a lazy and fail fast evaluation of a verification or a combination of verifications.
 *
 * <p>Instances of this class are immutable. </p>
 */
public class Verifiable {

	private final Supplier<VerificationResult> toVerify;

	private Verifiable(final Supplier<VerificationResult> toVerify) {
		this.toVerify = toVerify;
	}


	/**
	 * Combines {@code this} with another Verifiable {@code other} such that it verifies only if both verify. This allows to chain multiple Verifiable
	 * together. If {@code this} fails, {@code other} will not be evaluated (fail fast behavior).
	 *
	 * @param other the other Verifiable to combine with {@code this}. Not null.
	 * @return the combination of {@code this} with {@code other} as a new Verifiable.
	 */
	public Verifiable and(final Verifiable other) {
		checkNotNull(other);
		return new Verifiable(() -> {
			VerificationResult thisResult = this.verify();
			return thisResult.isVerified() ? other.verify() : thisResult;
		});
	}

	/**
	 * Evaluates the verification.
	 *
	 * @return the evaluated {@link VerificationResult}.
	 */
	public VerificationResult verify() {
		return toVerify.get();
	}

	/**
	 * Creates a Verifiable returning a {@link VerificationSuccess} when {@code toVerify} evaluates to {@code true}, or a {@link
	 * VerificationFailure} containing {@code errorMessage} when {@code toVerify} evaluates to {@code false}.
	 *
	 * @param toVerify     a supplier of a boolean condition to verify. Not null.
	 * @param errorMessage the error message when {@code toVerify} evaluates to {@code false}. Not null.
	 * @return a Verifiable based on {@code toVerify} condition.
	 */
	public static Verifiable create(final BooleanSupplier toVerify, final String errorMessage) {
		checkNotNull(toVerify);
		checkNotNull(errorMessage);
		return new Verifiable(() -> toVerify.getAsBoolean() ? VerificationSuccess.INSTANCE : new VerificationFailure(errorMessage));
	}

	/**
	 * Adds an error message to the VerificationResult in case of failure.
	 * @param errorMessage the errorMessage to add. Not null.
	 * @return a new Verifiable.
	 */
	public Verifiable addErrorMessage(final String errorMessage) {
		checkNotNull(errorMessage);

		return new Verifiable(() -> {
			VerificationResult result = this.verify();
			return result.isVerified() ? result : ((VerificationFailure) result).addErrorMessage(errorMessage);
		});
	}
}