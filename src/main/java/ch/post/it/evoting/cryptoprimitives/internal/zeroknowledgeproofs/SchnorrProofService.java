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
package ch.post.it.evoting.cryptoprimitives.internal.zeroknowledgeproofs;

import static ch.post.it.evoting.cryptoprimitives.internal.utils.ConversionsInternal.byteArrayToInteger;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

import ch.post.it.evoting.cryptoprimitives.hashing.HashableBigInteger;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableList;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableString;
import ch.post.it.evoting.cryptoprimitives.internal.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.internal.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.zeroknowledgeproofs.SchnorrProof;
import ch.post.it.evoting.cryptoprimitives.zeroknowledgeproofs.ZeroKnowledgeProof;

@SuppressWarnings("java:S117")
public class SchnorrProofService {

	private static final String GEN_SCHNORR_PROOF_SERVICE = "SchnorrProof";
	private final RandomService randomService;
	private final HashService hashService;

	public SchnorrProofService(final RandomService randomService, final HashService hashService) {
		this.randomService = checkNotNull(randomService);
		this.hashService = checkNotNull(hashService);
	}

	/**
	 * Computes the phi-function for a Schnorr proof.
	 *
	 * @param exponent x ∈ Z<sub>q</sub>. Not null.
	 * @return y
	 * @throws NullPointerException if any of the parameters is null.
	 */
	static GqElement computePhiSchnorr(final ZqElement exponent, final GqElement base) {

		checkNotNull(exponent);
		checkNotNull(base);

		// Cross group checking.
		checkArgument(exponent.getGroup().hasSameOrderAs(base.getGroup()),
				"The exponent must have the same group order as the base.");

		final ZqElement x = exponent;
		final GqElement g = base;

		return g.exponentiate(x);
	}

	/**
	 * @see ZeroKnowledgeProof#genSchnorrProof(ZqElement, GqElement, List<String>)
	 */
	public SchnorrProof genSchnorrProof(final ZqElement witness, final GqElement statement, final List<String> auxiliaryInformation) {

		checkNotNull(witness);
		checkNotNull(statement);
		checkNotNull(auxiliaryInformation);
		checkArgument(auxiliaryInformation.stream().allMatch(Objects::nonNull), "The auxiliary information must not contain null objects.");
		checkArgument(statement.equals(statement.getGroup().getGenerator().exponentiate(witness)));

		// Cross group checking.
		checkArgument(witness.getGroup().hasSameOrderAs(statement.getGroup()),
				"The witness must have the same group order as the statement.");

		// Context.
		final GqGroup gqGroup = statement.getGroup();
		final ZqGroup zqGroup = witness.getGroup();
		final BigInteger q = gqGroup.getQ();
		final GqElement g = gqGroup.getGenerator();
		final BigInteger p = gqGroup.getP();

		// Variables.
		final List<String> i_aux = List.copyOf(auxiliaryInformation);
		final GqElement y = statement;
		final ZqElement x = witness;

		// Operation.
		final BigInteger b = randomService.genRandomInteger(q);
		final GqElement c = computePhiSchnorr(ZqElement.create(b, zqGroup), g);
		final HashableList f = HashableList.of(HashableBigInteger.from(p), HashableBigInteger.from(q), g);

		final HashableList h_aux;
		if (!i_aux.isEmpty()) {
			h_aux = HashableList.of(HashableString.from(GEN_SCHNORR_PROOF_SERVICE),
					HashableList.from(i_aux.stream()
							.map(HashableString::from)
							.toList()));
		} else {
			h_aux = HashableList.of(HashableString.from(GEN_SCHNORR_PROOF_SERVICE));
		}

		final BigInteger eValue = byteArrayToInteger(hashService.recursiveHash(f, y, c, h_aux));
		final ZqElement e = ZqElement.create(eValue, zqGroup);
		final ZqElement bElement = ZqElement.create(b, zqGroup);
		final ZqElement z = bElement.add(e.multiply(x));

		return new SchnorrProof(e, z);
	}

	/**
	 * @see ZeroKnowledgeProof#verifySchnorrProof(SchnorrProof, GqElement, List<String>)
	 */
	public boolean verifySchnorrProof(final SchnorrProof proof, final GqElement statement, final List<String> auxiliaryInformation) {

		checkNotNull(proof);
		checkNotNull(statement);
		checkNotNull(auxiliaryInformation);

		checkArgument(auxiliaryInformation.stream().allMatch(Objects::nonNull), "The auxiliary information must not contain null objects.");

		// Cross group checking.
		checkArgument(proof.getGroup().hasSameOrderAs(statement.getGroup()),
				"The proof must have the same group order as the statement.");

		// Context.
		final GqGroup gqGroup = statement.getGroup();
		final BigInteger p = gqGroup.getP();
		final BigInteger q = gqGroup.getQ();
		final GqElement g = gqGroup.getGenerator();

		// Variables.
		final List<String> i_aux = List.copyOf(auxiliaryInformation);
		final ZqElement e = proof.get_e();
		final ZqElement z = proof.get_z();
		final GqElement y = statement;

		// Operation.
		final GqElement x = computePhiSchnorr(z, g);
		final HashableList f = HashableList.of(HashableBigInteger.from(p), HashableBigInteger.from(q), g);
		final GqElement c_prime = x.multiply(y.exponentiate(e.negate()));

		final HashableList h_aux;
		if (!i_aux.isEmpty()) {
			h_aux = HashableList.of(HashableString.from(GEN_SCHNORR_PROOF_SERVICE),
					HashableList.from(i_aux.stream()
							.map(HashableString::from)
							.toList()));
		} else {
			h_aux = HashableList.of(HashableString.from(GEN_SCHNORR_PROOF_SERVICE));
		}

		final byte[] h = hashService.recursiveHash(f, y, c_prime, h_aux);

		final BigInteger e_prime_value = byteArrayToInteger(h);
		final ZqElement e_prime = ZqElement.create(e_prime_value, ZqGroup.sameOrderAs(gqGroup));
		return e.equals(e_prime);
	}
}
