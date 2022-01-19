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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedList;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.utils.Verifiable;
import ch.post.it.evoting.cryptoprimitives.utils.VerificationResult;

@DisplayName("A Verifiable")
class VerifiableTest {

	@Nested
	@DisplayName("calling verify")
	class Verify {

		@Test
		@DisplayName("on failed verification returns false")
		void verifyFailedVerificationResultReturnFalse() {
			final Verifiable verifiable = Verifiable.create(() -> false, "Error message 1.");
			assertFalse(verifiable.verify().isVerified());
		}

		@Test
		@DisplayName("on success verification returns true")
		void verifySuccessVerificationResultReturnTrue() {
			final Verifiable verifiable = Verifiable.create(() -> true, "Error message 1.");
			assertTrue(verifiable.verify().isVerified());
		}

	}

	@Nested
	@DisplayName("calling 'and' ")
	class And {

		final Verifiable failVerifiable = Verifiable.create(() -> false, "Error message 1.");
		final Verifiable otherFailVerifiable = Verifiable.create(() -> false, "Error message other.");
		final Verifiable successVerifiable = Verifiable.create(() -> true, "This message should not appear");
		final Verifiable otherSuccessVerifiable = Verifiable.create(() -> true, "This message should not appear too.");

		@Test
		@DisplayName("with null other throws NullPointerException")
		void andNullParam() {
			assertThrows(NullPointerException.class, () -> failVerifiable.and(null));
		}

		@Test
		@DisplayName("correctly combines failed VerificationResults")
		void andCorrectlyCombinesFailedVerifications() {
			// The "and" fails fast and thus does not evaluate "other".
			final LinkedList<String> expectedMessages = new LinkedList<>();
			expectedMessages.push("Error message 1.");

			final VerificationResult verify = failVerifiable.and(otherFailVerifiable).verify();
			assertFalse(verify.isVerified());
			assertArrayEquals(expectedMessages.toArray(), verify.getErrorMessages().toArray());
		}

		@Test
		@DisplayName("correctly combines succeeded and failed VerificationResults")
		void andCorrectlyCombinesSucceededFailedVerifications() {
			final LinkedList<String> expectedMessages = new LinkedList<>();
			expectedMessages.push("Error message other.");

			final VerificationResult verify = successVerifiable.and(otherFailVerifiable).verify();
			assertFalse(verify.isVerified());
			assertArrayEquals(expectedMessages.toArray(), verify.getErrorMessages().toArray());
		}

		@Test
		@DisplayName("correctly combines failed and succeeded VerificationResults")
		void andCorrectlyCombinesFailedSucceededVerifications() {
			final LinkedList<String> expectedMessages = new LinkedList<>();
			expectedMessages.push("Error message 1.");

			final VerificationResult verify = failVerifiable.and(otherSuccessVerifiable).verify();
			assertFalse(verify.isVerified());
			assertArrayEquals(expectedMessages.toArray(), verify.getErrorMessages().toArray());
		}

		@Test
		@DisplayName("correctly combines succeeded VerificationResults")
		void andCorrectlyCombinesSucceededVerifications() {
			final VerificationResult verify = successVerifiable.and(otherSuccessVerifiable).verify();
			assertTrue(verify.isVerified());
		}
	}

	@Nested
	@DisplayName("created with ")
	class Create {

		@Test
		@DisplayName("null parameters throws NullPointerException")
		void createdWithNullParams() {
			assertThrows(NullPointerException.class, () -> Verifiable.create(null, "Error message 1."));
			assertThrows(NullPointerException.class, () -> Verifiable.create(() -> false, null));
		}

		@Test
		@DisplayName("supplier returning false is not verified")
		void createdWithFalseSupplier() {
			final Verifiable verifiable = Verifiable.create(() -> false, "Error message 1.");

			assertFalse(verifiable.verify().isVerified());
			assertEquals(1, verifiable.verify().getErrorMessages().size());
			assertEquals("Error message 1.", verifiable.verify().getErrorMessages().getFirst());
		}

		@Test
		@DisplayName("supplier returning true is verified")
		void createdWithTrueSupplier() {
			final Verifiable verifiable = Verifiable.create(() -> true, "This message should not appear.");
			assertTrue(verifiable.verify().isVerified());
		}
	}

	@Nested
	@DisplayName("adding an error message ")
	class AddError {

		private final String testMessage = "TEST";
		private final Verifiable successVerifiable = Verifiable.create(() -> true, "Not used");
		private final String failureMessage = "Used";
		private final Verifiable failureVerifiable = Verifiable.create(() -> false, failureMessage);

		@Test
		@DisplayName("which is null throws NullPointerException")
		void addNullThrows() {
			assertThrows(NullPointerException.class, () -> successVerifiable.addErrorMessage(null));
		}

		@Test
		@DisplayName("correctly adds it to VerificationResult after evaluation")
		void addMessageIsAddedToVerificationResultAfterEvaluation() {
			final Verifiable failureWithExtraMessage = failureVerifiable.addErrorMessage(testMessage);
			final LinkedList<String> expected = new LinkedList<>();
			expected.push(failureMessage);
			expected.push(testMessage);

			assertFalse(failureWithExtraMessage.verify().isVerified());
			assertArrayEquals(expected.toArray(), failureWithExtraMessage.verify().getErrorMessages().toArray());
		}

		@Test
		@DisplayName("to a successful Verification does nothing")
		void addMessageToSuccessfulVerificationDoesNothing() {
			final Verifiable successfulWithAddedMessage = successVerifiable.addErrorMessage(testMessage);
			final VerificationResult verificationResult = successfulWithAddedMessage.verify();

			assertTrue(verificationResult.isVerified());
			assertThrows(UnsupportedOperationException.class, verificationResult::getErrorMessages);
		}

		@Test
		@DisplayName("returns a new Verifiable instance")
		void addMessageReturnsNewInstance() {
			final Verifiable other = failureVerifiable.addErrorMessage(testMessage);

			assertNotEquals(other, failureVerifiable);
		}
	}
}