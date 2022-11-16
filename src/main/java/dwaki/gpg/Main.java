package dwaki.gpg;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;

public class Main {

	public static void main(String[] args) {

		URL privateKey = Main.class.getResource("/private.pgp");
		URL publicKey = Main.class.getResource("/public.pgp");
		URL file = Main.class.getResource("/Original.txt");

		File encryptedFile = new File("gpg/encryptedFile");
		
		System.out.println("Encryption Starts...");

		File originalFile;
		try {
			originalFile = new File(file.toURI());

			try (OutputStream fos = Files.newOutputStream(encryptedFile.toPath())) {
				new Encryption().encrypt(fos, Files.newInputStream(originalFile.toPath()), originalFile.length(),
						publicKey.openStream());
			}

		} catch (URISyntaxException | IOException e) {

			e.printStackTrace();
		}
		
		System.out.println("Encryption Ends...");

	}

}
