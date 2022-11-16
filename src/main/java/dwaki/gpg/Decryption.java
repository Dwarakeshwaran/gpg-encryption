package dwaki.gpg;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.security.Security;
import java.util.Iterator;
import java.util.Objects;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;

public class Decryption {

	static {
		// Add Bouncy castle to JVM
		if (Objects.isNull(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME))) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	private final char[] passCode;
	private final PGPSecretKeyRingCollection pgpSecretKeyRingCollection;

	public Decryption(InputStream privateKeyIn, String passCode) throws IOException, PGPException {
		this.passCode = passCode.toCharArray();
		this.pgpSecretKeyRingCollection = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(privateKeyIn),
				new JcaKeyFingerprintCalculator());
	}

	public Decryption(String privateKeyStr, String passCode) throws IOException, PGPException {
		this(IOUtils.toInputStream(privateKeyStr, Charset.defaultCharset()), passCode);
	}

	public void decrypt(InputStream encryptedIn, OutputStream clearOut) throws PGPException, IOException {
		// Removing armour and returning the underlying binary encrypted stream
		encryptedIn = PGPUtil.getDecoderStream(encryptedIn);
		JcaPGPObjectFactory pgpObjectFactory = new JcaPGPObjectFactory(encryptedIn);

		Object obj = pgpObjectFactory.nextObject();
		// The first object might be a marker packet
		PGPEncryptedDataList pgpEncryptedDataList = (obj instanceof PGPEncryptedDataList) ? (PGPEncryptedDataList) obj
				: (PGPEncryptedDataList) pgpObjectFactory.nextObject();

		PGPPrivateKey pgpPrivateKey = null;
		PGPPublicKeyEncryptedData publicKeyEncryptedData = null;

		Iterator<PGPEncryptedData> encryptedDataItr = pgpEncryptedDataList.getEncryptedDataObjects();
		while (pgpPrivateKey == null && encryptedDataItr.hasNext()) {
			publicKeyEncryptedData = (PGPPublicKeyEncryptedData) encryptedDataItr.next();
			pgpPrivateKey = findSecretKey(publicKeyEncryptedData.getKeyID());
		}

		if (Objects.isNull(publicKeyEncryptedData)) {
			throw new PGPException("Could not generate PGPPublicKeyEncryptedData object");
		}

		if (pgpPrivateKey == null) {
			throw new PGPException("Could Not Extract private key");
		}
		decrypt(clearOut, pgpPrivateKey, publicKeyEncryptedData);
	}

	private PGPPrivateKey findSecretKey(long keyID) throws PGPException {
		PGPSecretKey pgpSecretKey = pgpSecretKeyRingCollection.getSecretKey(keyID);
		return pgpSecretKey == null ? null
				: pgpSecretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder()
						.setProvider(BouncyCastleProvider.PROVIDER_NAME).build(passCode));
	}

	private void decrypt(OutputStream clearOut, PGPPrivateKey pgpPrivateKey,
			PGPPublicKeyEncryptedData publicKeyEncryptedData) throws IOException, PGPException {
		PublicKeyDataDecryptorFactory decryptorFactory = new JcePublicKeyDataDecryptorFactoryBuilder()
				.setProvider(BouncyCastleProvider.PROVIDER_NAME).build(pgpPrivateKey);
		InputStream decryptedCompressedIn = publicKeyEncryptedData.getDataStream(decryptorFactory);

		JcaPGPObjectFactory decCompObjFac = new JcaPGPObjectFactory(decryptedCompressedIn);
		PGPCompressedData pgpCompressedData = (PGPCompressedData) decCompObjFac.nextObject();

		InputStream compressedDataStream = new BufferedInputStream(pgpCompressedData.getDataStream());
		JcaPGPObjectFactory pgpCompObjFac = new JcaPGPObjectFactory(compressedDataStream);

		Object message = pgpCompObjFac.nextObject();

		if (message instanceof PGPLiteralData) {
			PGPLiteralData pgpLiteralData = (PGPLiteralData) message;
			InputStream decDataStream = pgpLiteralData.getInputStream();
			IOUtils.copy(decDataStream, clearOut);
			clearOut.close();
		} else if (message instanceof PGPOnePassSignatureList) {
			throw new PGPException("Encrypted message contains a signed message not literal data");
		} else {
			throw new PGPException("Message is not a simple encrypted file - Type Unknown");
		}
		// Performing Integrity check
		if (publicKeyEncryptedData.isIntegrityProtected() && !publicKeyEncryptedData.verify()) {

			throw new PGPException("Message failed integrity check");

		}
	}

}
