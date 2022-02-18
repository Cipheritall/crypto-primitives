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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedList;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("A VerificationResult")
class VerificationResultTest {

	private final String initialErrorMessage = "Error message 0.";
	private final VerificationFailure verificationFailure = new VerificationFailure(initialErrorMessage);
	private final VerificationSuccess verificationSuccess = VerificationSuccess.INSTANCE;

	@Test
	@DisplayName("constructed as a verification failure with valid error message is not verified and contains correct message")
	void constructorWithValidMessage() {
		assertFalse(verificationFailure.isVerified());
		assertEquals(1, verificationFailure.getErrorMessages().size());
		assertEquals(initialErrorMessage, verificationFailure.getErrorMessages().getFirst());
	}

	@Test
	@DisplayName("constructed as a verification success is valid")
	void aVerificationSuccessIsValid() {
		assertTrue(verificationSuccess.isVerified());
	}

	@Test
	@DisplayName("which is a verification success calling getErrorMessages throws UnsupportedOperationException")
	void aVerificationSuccessThrowsOnGetMessages() {
		assertThrows(UnsupportedOperationException.class, verificationSuccess::getErrorMessages);
	}

	@Test
	@DisplayName("constructed with null message throws NullPointerException")
	void constructorWithNullParam() {
		assertThrows(NullPointerException.class, () -> new VerificationFailure(null));
	}

	@Test
	@DisplayName("with added valid error message correctly adds")
	void addErrorMessageWithValidMessage() {
		final VerificationFailure newVerificationResult = verificationFailure.addErrorMessage("Error message 1.");

		assertEquals(1, verificationFailure.getErrorMessages().size());
		assertEquals(initialErrorMessage, verificationFailure.getErrorMessages().getFirst());

		final LinkedList<String> expectedMessages = new LinkedList<>();
		expectedMessages.push(initialErrorMessage);
		expectedMessages.push("Error message 1.");

		assertEquals(2, newVerificationResult.getErrorMessages().size());
		assertArrayEquals(expectedMessages.toArray(), newVerificationResult.getErrorMessages().toArray());
	}

	@Test
	@DisplayName("with added null message throws NullPointerException")
	void addErrorMessageWithNullParam() {
		assertThrows(NullPointerException.class, () -> verificationFailure.addErrorMessage(null));
	}
}