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

import static ch.post.it.evoting.cryptoprimitives.SameGroupVector.toSameGroupVector;

import java.math.BigInteger;
import java.util.Arrays;

import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.JsonData;

class ArgumentParser {

	private final GqGroup gqGroup;
	private final ZqGroup zqGroup;

	ArgumentParser(final GqGroup gqGroup) {
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
		final SameGroupVector<GqElement, GqGroup> cd = Arrays.stream(cdValues)
				.map(bi -> GqElement.create(bi, gqGroup))
				.collect(toSameGroupVector());
		final SameGroupVector<ZqElement, ZqGroup> aPrime = Arrays.stream(aValues)
				.map(bi -> ZqElement.create(bi, zqGroup))
				.collect(toSameGroupVector());
		final SameGroupVector<ZqElement, ZqGroup> bPrime = Arrays.stream(bValues)
				.map(bi -> ZqElement.create(bi, zqGroup))
				.collect(toSameGroupVector());
		final ZqElement r = ZqElement.create(rValue, zqGroup);
		final ZqElement s = ZqElement.create(sValue, zqGroup);
		final ZqElement t = ZqElement.create(tValue, zqGroup);

		return new ZeroArgument.Builder()
				.withCA0(cA0)
				.withCBm(cBm)
				.withCd(cd)
				.withAPrime(aPrime)
				.withBPrime(bPrime)
				.withRPrime(r)
				.withSPrime(s)
				.withTPrime(t)
				.build();
	}

	HadamardArgument parseHadamardArgument(final JsonData hadamardArgumentData) {
		final BigInteger[] cUpperBValues = hadamardArgumentData.get("cUpperB", BigInteger[].class);
		SameGroupVector<GqElement, GqGroup> cUpperB = Arrays.stream(cUpperBValues)
				.map(bi -> GqElement.create(bi, gqGroup))
				.collect(toSameGroupVector());

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
		final SameGroupVector<ZqElement, ZqGroup> aTilde = Arrays.stream(aTildeValues)
				.map(bi -> ZqElement.create(bi, zqGroup))
				.collect(toSameGroupVector());
		final SameGroupVector<ZqElement, ZqGroup> bTilde = Arrays.stream(bTildeValues)
				.map(bi -> ZqElement.create(bi, zqGroup))
				.collect(toSameGroupVector());
		final ZqElement rTilde = ZqElement.create(rTildeValue, zqGroup);
		final ZqElement sTilde = ZqElement.create(sTildeValue, zqGroup);

		return new SingleValueProductArgument.Builder()
				.withCd(cd)
				.withCLowerDelta(cLowerDelta)
				.withCUpperDelta(cUpperDelta)
				.withATilde(aTilde)
				.withBTilde(bTilde)
				.withRTilde(rTilde)
				.withSTilde(sTilde)
				.build();
	}

}