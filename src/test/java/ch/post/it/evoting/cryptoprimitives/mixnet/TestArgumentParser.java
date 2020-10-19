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

import static ch.post.it.evoting.cryptoprimitives.GroupVector.toGroupVector;
import static java.util.stream.Collectors.collectingAndThen;
import static java.util.stream.Collectors.toList;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.stream.StreamSupport;

import ch.post.it.evoting.cryptoprimitives.GroupMatrix;
import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.JsonData;

class TestArgumentParser {

	private final GqGroup gqGroup;
	private final ZqGroup zqGroup;

	TestArgumentParser(final GqGroup gqGroup) {
		this.gqGroup = gqGroup;
		this.zqGroup = ZqGroup.sameOrderAs(gqGroup);
	}

	ZeroArgument parseZeroArgument(final JsonData zeroArgumentData) {

		final BigInteger cA0Value = zeroArgumentData.get("c_a0", BigInteger.class);
		final BigInteger cBmValue = zeroArgumentData.get("c_bm", BigInteger.class);
		final BigInteger[] cdValues = zeroArgumentData.get("c_d", BigInteger[].class);
		final BigInteger[] aValues = zeroArgumentData.get("a", BigInteger[].class);
		final BigInteger[] bValues = zeroArgumentData.get("b", BigInteger[].class);
		final BigInteger rValue = zeroArgumentData.get("r", BigInteger.class);
		final BigInteger sValue = zeroArgumentData.get("s", BigInteger.class);
		final BigInteger tValue = zeroArgumentData.get("t", BigInteger.class);

		final GqElement cA0 = GqElement.create(cA0Value, gqGroup);
		final GqElement cBm = GqElement.create(cBmValue, gqGroup);
		final GroupVector<GqElement, GqGroup> cd = Arrays.stream(cdValues)
				.map(bi -> GqElement.create(bi, gqGroup))
				.collect(toGroupVector());
		final GroupVector<ZqElement, ZqGroup> aPrime = Arrays.stream(aValues)
				.map(bi -> ZqElement.create(bi, zqGroup))
				.collect(toGroupVector());
		final GroupVector<ZqElement, ZqGroup> bPrime = Arrays.stream(bValues)
				.map(bi -> ZqElement.create(bi, zqGroup))
				.collect(toGroupVector());
		final ZqElement r = ZqElement.create(rValue, zqGroup);
		final ZqElement s = ZqElement.create(sValue, zqGroup);
		final ZqElement t = ZqElement.create(tValue, zqGroup);

		return new ZeroArgument.Builder()
				.with_c_A_0(cA0)
				.with_c_B_m(cBm)
				.with_c_d(cd)
				.with_a_prime(aPrime)
				.with_b_prime(bPrime)
				.with_r_prime(r)
				.with_s_prime(s)
				.with_t_prime(t)
				.build();
	}

	HadamardArgument parseHadamardArgument(final JsonData hadamardArgumentData) {
		final BigInteger[] cUpperBValues = hadamardArgumentData.get("cUpperB", BigInteger[].class);
		GroupVector<GqElement, GqGroup> cUpperB = Arrays.stream(cUpperBValues)
				.map(bi -> GqElement.create(bi, gqGroup))
				.collect(toGroupVector());

		JsonData zeroArgumentData = hadamardArgumentData.getJsonData("zero_argument");
		ZeroArgument zeroArgument = parseZeroArgument(zeroArgumentData);

		return new HadamardArgument(cUpperB, zeroArgument);
	}

	SingleValueProductArgument parseSingleValueProductArgument(final JsonData svpArgumentData) {
		final BigInteger cdValue = svpArgumentData.get("c_d", BigInteger.class);
		final BigInteger cLowerDeltaValue = svpArgumentData.get("c_lower_delta", BigInteger.class);
		final BigInteger cUpperDeltaValue = svpArgumentData.get("c_upper_delta", BigInteger.class);
		final BigInteger[] aTildeValues = svpArgumentData.get("a_tilde", BigInteger[].class);
		final BigInteger[] bTildeValues = svpArgumentData.get("b_tilde", BigInteger[].class);
		final BigInteger rTildeValue = svpArgumentData.get("r_tilde", BigInteger.class);
		final BigInteger sTildeValue = svpArgumentData.get("s_tilde", BigInteger.class);

		final GqElement cd = GqElement.create(cdValue, gqGroup);
		final GqElement cLowerDelta = GqElement.create(cLowerDeltaValue, gqGroup);
		final GqElement cUpperDelta = GqElement.create(cUpperDeltaValue, gqGroup);
		final GroupVector<ZqElement, ZqGroup> aTilde = Arrays.stream(aTildeValues)
				.map(bi -> ZqElement.create(bi, zqGroup))
				.collect(toGroupVector());
		final GroupVector<ZqElement, ZqGroup> bTilde = Arrays.stream(bTildeValues)
				.map(bi -> ZqElement.create(bi, zqGroup))
				.collect(toGroupVector());
		final ZqElement rTilde = ZqElement.create(rTildeValue, zqGroup);
		final ZqElement sTilde = ZqElement.create(sTildeValue, zqGroup);

		return new SingleValueProductArgument.Builder()
				.with_c_d(cd)
				.with_c_delta(cLowerDelta)
				.with_c_Delta(cUpperDelta)
				.with_a_tilde(aTilde)
				.with_b_tilde(bTilde)
				.with_r_tilde(rTilde)
				.with_s_tilde(sTilde)
				.build();
	}

	MultiExponentiationArgument parseMultiExponentiationArgument(final JsonData multiExpArgumentData) {
		final BigInteger cA0Value = multiExpArgumentData.get("c_a_0", BigInteger.class);
		final BigInteger[] cBValues = multiExpArgumentData.get("c_b", BigInteger[].class);
		final JsonData eDataArray = multiExpArgumentData.getJsonData("e");
		final BigInteger[] aValues = multiExpArgumentData.get("a", BigInteger[].class);
		final BigInteger rValue = multiExpArgumentData.get("r", BigInteger.class);
		final BigInteger bValue = multiExpArgumentData.get("b", BigInteger.class);
		final BigInteger sValue = multiExpArgumentData.get("s", BigInteger.class);
		final BigInteger tauValue = multiExpArgumentData.get("tau", BigInteger.class);

		final GqElement cA0 = GqElement.create(cA0Value, gqGroup);
		final GroupVector<GqElement, GqGroup> cB = Arrays.stream(cBValues)
				.map(bi -> GqElement.create(bi, gqGroup))
				.collect(toGroupVector());
		final GroupVector<ZqElement, ZqGroup> a = Arrays.stream(aValues)
				.map(bi -> ZqElement.create(bi, zqGroup))
				.collect(toGroupVector());
		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> E = parseCiphertextVector(eDataArray);
		final ZqElement r = ZqElement.create(rValue, zqGroup);
		final ZqElement b = ZqElement.create(bValue, zqGroup);
		final ZqElement s = ZqElement.create(sValue, zqGroup);
		final ZqElement tau = ZqElement.create(tauValue, zqGroup);

		return new MultiExponentiationArgument.Builder()
				.with_c_A_0(cA0)
				.with_c_B(cB)
				.with_E(E)
				.with_a(a)
				.with_r(r)
				.with_b(b)
				.with_s(s)
				.with_tau(tau)
				.build();

	}
	ProductArgument parseProductArgument(final JsonData argumentData) {
		final SingleValueProductArgument singleValueProductArgument = this.parseSingleValueProductArgument(argumentData.getJsonData("single_vpa"));

		ProductArgument productArgument;
		final JsonData cbJsonData = argumentData.getJsonData("c_b");
		if (!cbJsonData.getJsonNode().isMissingNode()) {
			final BigInteger cbValue = argumentData.get("c_b", BigInteger.class);
			final GqElement cb = GqElement.create(cbValue, gqGroup);
			final HadamardArgument hadamardArgument = this.parseHadamardArgument(argumentData.getJsonData("hadamard_argument"));

			productArgument = new ProductArgument(cb, hadamardArgument, singleValueProductArgument);
		} else {
			productArgument = new ProductArgument(singleValueProductArgument);
		}
		return productArgument;
	}

	ElGamalMultiRecipientCiphertext parseCiphertext(final JsonData ciphertextData) {
		final BigInteger gammaValue = ciphertextData.get("gamma", BigInteger.class);
		final BigInteger[] phisValues = ciphertextData.get("phis", BigInteger[].class);

		final GqElement gamma = GqElement.create(gammaValue, gqGroup);
		final List<GqElement> phis = Arrays.stream(phisValues)
				.map(bi -> GqElement.create(bi, gqGroup))
				.collect(toList());

		return ElGamalMultiRecipientCiphertext.create(gamma, phis);
	}

	GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> parseCiphertextVector(final JsonData ciphertextsDataVector) {
		if (!ciphertextsDataVector.getJsonNode().isArray()) {
			throw new IllegalArgumentException("Provided jsonData does not wrap an array.");
		}

		return StreamSupport.stream(ciphertextsDataVector.getJsonNode().spliterator(), false)
				.map(node -> parseCiphertext(new JsonData(node)))
				.collect(toGroupVector());
	}

	GroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> parseCiphertextMatrix(final JsonData ciphertextDataMatrix) {
		if (!ciphertextDataMatrix.getJsonNode().isArray()) {
			throw new IllegalArgumentException("Provided jsonData does not wrap an array.");
		}

		return StreamSupport.stream(ciphertextDataMatrix.getJsonNode().spliterator(), false)
				.map(node -> parseCiphertextVector(new JsonData(node)))
				.collect(collectingAndThen(toList(), GroupMatrix::fromRows));
	}

}
