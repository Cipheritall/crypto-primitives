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
module ch.post.it.evoting.cryptoprimitives {
	requires com.google.common;
	requires org.bouncycastle.provider;
	requires org.bouncycastle.pkix;
	requires jnagmp;
	requires org.slf4j;
	exports ch.post.it.evoting.cryptoprimitives.elgamal;
	exports ch.post.it.evoting.cryptoprimitives.hashing;
	exports ch.post.it.evoting.cryptoprimitives.math;
	exports ch.post.it.evoting.cryptoprimitives.mixnet;
	exports ch.post.it.evoting.cryptoprimitives.securitylevel;
	exports ch.post.it.evoting.cryptoprimitives.signing;
	exports ch.post.it.evoting.cryptoprimitives.symmetric;
	exports ch.post.it.evoting.cryptoprimitives.utils;
	exports ch.post.it.evoting.cryptoprimitives.zeroknowledgeproofs;
}