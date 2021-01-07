package ch.post.it.evoting.cryptoprimitives;

import ch.post.it.evoting.cryptoprimitives.random.RandomService;

final class CryptoPrimitiveFacade implements CryptoPrimitiveService {

	private final RandomService randomService = new RandomService();

	@Override
	public String genRandomBase16String(final int length) {
		return randomService.genRandomBase16String(length);
	}

	@Override
	public String genRandomBase32String(final int length) {
		return randomService.genRandomBase32String(length);
	}

	@Override
	public String genRandomBase64String(final int length) {
		return randomService.genRandomBase64String(length);
	}

}
