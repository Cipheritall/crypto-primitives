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