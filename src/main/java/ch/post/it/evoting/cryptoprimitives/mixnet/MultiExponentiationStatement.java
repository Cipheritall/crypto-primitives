/*
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
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Objects;

import ch.post.it.evoting.cryptoprimitives.GroupMatrix;
import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;

/**
 * Value class representing the statement for the multi exponent argument.
 * <p>
 * Instances of this class are immutable.
 */
final class MultiExponentiationStatement {

	private final GroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> CMatrix;
	private final ElGamalMultiRecipientCiphertext C;
	private final GroupVector<GqElement, GqGroup> cA;

	private final GqGroup group;
	private final int m;
	private final int n;
	private final int l;

	/**
	 * <p>Creates a multi exponentiation statement.</p>
	 * <p>
	 * The arguments must abide by the following conditions:
	 * <ul>
	 *     <li>All arguments must be non null</li>
	 *     <li>All arguments must belong to the same GqGroup</li>
	 *     <li>The commitment to A must be the same size as the number of rows of the ciphertext matrix.</li>
	 * </ul>
	 *
	 * @param ciphertextMatrix (C<sub>0</sub>, ..., C<sub>m-1</sub>), the matrix of ciphertexts of size m x n
	 * @param ciphertextC      C, the re-encrypted multi exponentiation product
	 * @param commitmentA      c<sub>A</sub>, the commitment to the matrix A of size m
	 */
	MultiExponentiationStatement(final GroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> ciphertextMatrix,
			final ElGamalMultiRecipientCiphertext ciphertextC, final GroupVector<GqElement, GqGroup> commitmentA) {

		//Null checking
		checkNotNull(ciphertextMatrix);
		checkNotNull(ciphertextC);
		checkNotNull(commitmentA);

		//Dimension checking
		checkArgument(ciphertextMatrix.isEmpty() && commitmentA.isEmpty() || ciphertextMatrix.numRows() == commitmentA.size(),
				"The commitment must be the same size as the number of rows of the ciphertext matrix.");

		//Group checking
		if (!ciphertextMatrix.isEmpty()) {
			checkArgument(ciphertextMatrix.getGroup().equals(ciphertextC.getGroup()),
					"The ciphertext matrix and the ciphertext C must be from the same group.");
			checkArgument(ciphertextMatrix.getGroup().equals(commitmentA.getGroup()),
					"The ciphertext matrix and the commitment must be from the same group.");
		}

		this.CMatrix = ciphertextMatrix;
		this.C = ciphertextC;
		this.cA = commitmentA;

		this.group = ciphertextMatrix.getGroup();
		this.m = ciphertextMatrix.numRows();
		this.n = ciphertextMatrix.numColumns();
		this.l = ciphertextMatrix.getElementSize();
	}

	GroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> getCMatrix() {
		return CMatrix;
	}

	ElGamalMultiRecipientCiphertext getC() {
		return C;
	}

	GroupVector<GqElement, GqGroup> getcA() {
		return cA;
	}

	GqGroup getGroup() {
		return group;
	}

	int getM() {
		return m;
	}

	int getN() {
		return n;
	}

	@Override
	public boolean equals(final Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		final MultiExponentiationStatement that = (MultiExponentiationStatement) o;
		return CMatrix.equals(that.CMatrix) && C.equals(that.C) && cA.equals(that.cA);
	}

	@Override
	public int hashCode() {
		return Objects.hash(CMatrix, C, cA);
	}

	public int getL() {
		return l;
	}
}
