package ch.post.it.evoting.cryptoprimitives.symmetric;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.google.common.annotations.VisibleForTesting;

import ch.post.it.evoting.cryptoprimitives.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.symmetric.SymmetricAuthenticatedEncryptionService.SymmetricCiphertext;

public class SymmetricService implements Symmetric {

	private final SymmetricAuthenticatedEncryptionService symmetricAuthenticatedEncryptionService;

	/**
	 * Instantiates an authenticated symmetric encryption service.
	 */
	public SymmetricService() {
		final RandomService randomService = new RandomService();

		symmetricAuthenticatedEncryptionService = new SymmetricAuthenticatedEncryptionService(randomService,
				SymmetricAuthenticatedEncryptionService.SymmetricEncryptionAlgorithm.AES_GCM_NOPADDING);
	}

	@VisibleForTesting
	public SymmetricService(final RandomService randomService) {
		symmetricAuthenticatedEncryptionService = new SymmetricAuthenticatedEncryptionService(randomService,
				SymmetricAuthenticatedEncryptionService.SymmetricEncryptionAlgorithm.AES_GCM_NOPADDING);
	}

	@Override
	public SymmetricCiphertext genCiphertextSymmetric(final byte[] encryptionKey, final byte[] plainText,
			final List<String> associatedData)
			throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
			BadPaddingException, InvalidKeyException {

		return symmetricAuthenticatedEncryptionService.genCiphertextSymmetric(encryptionKey, plainText, associatedData);
	}

	@Override
	public byte[] getPlaintextSymmetric(final byte[] encryptionKey, final byte[] cipherText,
			final byte[] nonce, final List<String> associatedData)
			throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
			BadPaddingException, InvalidKeyException {

		return symmetricAuthenticatedEncryptionService.getPlaintextSymmetric(encryptionKey, cipherText, nonce, associatedData);
	}
}
