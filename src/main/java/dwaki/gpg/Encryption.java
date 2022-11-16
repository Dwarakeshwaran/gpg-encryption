package dwaki.gpg;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.Objects;
import java.util.Optional;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

public class Encryption {

	static {
		// Add Bouncy castle to JVM
		if (Objects.isNull(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME))) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	private int compressionAlgorithm = CompressionAlgorithmTags.ZIP;
	private int symmetricKeyAlgorithm = SymmetricKeyAlgorithmTags.AES_128;
	private boolean withIntegrityCheck = true;
	private boolean armor = true;
	private int bufferSize = 1 << 16;

	public void encrypt(OutputStream encryptOut, InputStream clearIn, long length, InputStream publicKeyIn) {

		try {
			PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(compressionAlgorithm);

			JcePGPDataEncryptorBuilder encryptorBuilder = new JcePGPDataEncryptorBuilder(symmetricKeyAlgorithm)
					.setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom())
					.setProvider(BouncyCastleProvider.PROVIDER_NAME);

			PGPEncryptedDataGenerator pgpEncryptedDataGenerator = new PGPEncryptedDataGenerator(encryptorBuilder);

			JcePublicKeyKeyEncryptionMethodGenerator keyEncryptionMethod = new JcePublicKeyKeyEncryptionMethodGenerator(
					getPublicKey(publicKeyIn));
			
			pgpEncryptedDataGenerator.addMethod(keyEncryptionMethod);
			
			if (armor) {
	            encryptOut = new ArmoredOutputStream(encryptOut);
	        }
			System.out.println(bufferSize);
			OutputStream cipherOutStream = pgpEncryptedDataGenerator.open(encryptOut, new byte[bufferSize]);
			
			copyAsLiteralData(compressedDataGenerator.open(cipherOutStream), clearIn, length, bufferSize);
			
			compressedDataGenerator.close();
	        cipherOutStream.close();
	        encryptOut.close();
			
			
		} catch (IOException | PGPException e) {

			e.printStackTrace();
		}

	}

	private PGPPublicKey getPublicKey(InputStream keyInputStream) throws IOException, PGPException {
		PGPPublicKeyRingCollection pgpPublicKeyRings = new PGPPublicKeyRingCollection(
				PGPUtil.getDecoderStream(keyInputStream), new JcaKeyFingerprintCalculator());
		Iterator<PGPPublicKeyRing> keyRingIterator = pgpPublicKeyRings.getKeyRings();
		while (keyRingIterator.hasNext()) {
			PGPPublicKeyRing pgpPublicKeyRing = keyRingIterator.next();
			Optional<PGPPublicKey> pgpPublicKey = extractPGPKeyFromRing(pgpPublicKeyRing);
			if (pgpPublicKey.isPresent()) {
				return pgpPublicKey.get();
			}
		}
		throw new PGPException("Invalid public key");
	}

	private Optional<PGPPublicKey> extractPGPKeyFromRing(PGPPublicKeyRing pgpPublicKeyRing) {
		for (PGPPublicKey publicKey : pgpPublicKeyRing) {
			if (publicKey.isEncryptionKey()) {
				return Optional.of(publicKey);
			}
		}
		return Optional.empty();
	}
	
	public void copyAsLiteralData(OutputStream outputStream, InputStream in, long length, int bufferSize) throws IOException {
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        OutputStream pOut = lData.open(outputStream, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE,
                Date.from(LocalDateTime.now().toInstant(ZoneOffset.UTC)), new byte[bufferSize]);
        byte[] buff = new byte[bufferSize];
        try {
            int len;
            long totalBytesWritten = 0L;
            while (totalBytesWritten <= length && (len = in.read(buff)) > 0) {
                pOut.write(buff, 0, len);
                totalBytesWritten += len;
            }
            pOut.close();
        } finally {
            // Clearing buffer
            Arrays.fill(buff, (byte) 0);
            // Closing inputstream
            in.close();
        }
    }

}
