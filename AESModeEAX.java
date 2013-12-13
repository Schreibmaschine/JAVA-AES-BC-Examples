import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Random;

import javax.crypto.NoSuchPaddingException;

import org.spongycastle.crypto.BlockCipher;
import org.spongycastle.crypto.CipherParameters;
import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.engines.AESEngine;
import org.spongycastle.crypto.modes.EAXBlockCipher;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;

public class AESModeEAX {
	private final BlockCipher AESCipher = new AESEngine();
	private KeyParameter key;
	private byte[] salt = new byte[8];

	public void setKey(KeyParameter key) {
		this.key = key;
	}

	public void setSalt(byte[] salt) {
		this.salt = salt;
	}

	public byte[] getSaltFromFile(File file) throws IOException {
		InputStream inBuf = (new BufferedInputStream(new FileInputStream(file)));
		inBuf.read(salt);
		inBuf.close();
		return salt;
	}

	private byte[] generateIV() {
		byte[] iv = new byte[16];
		Random r = new Random();
		r.nextBytes(iv);
		return iv;
	}

	public void restAES() {
		AESCipher.reset();
	}

	public void encrypt(File in, File out) throws InvalidKeyException,
			NoSuchAlgorithmException, NoSuchProviderException,
			NoSuchPaddingException, InvalidAlgorithmParameterException,
			IOException, IllegalStateException, InvalidCipherTextException {
		processing(in, out, true);
	}

	public void decrypt(File in, File out) throws InvalidKeyException,
			NoSuchAlgorithmException, NoSuchProviderException,
			NoSuchPaddingException, InvalidAlgorithmParameterException,
			IOException, IllegalStateException, InvalidCipherTextException {
		processing(in, out, false);
	}

	private void processing(File in, File out, boolean encrypt)
			throws IOException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException,
			IllegalStateException, InvalidCipherTextException {
		InputStream inBuf = (new BufferedInputStream(new FileInputStream(in)));

		OutputStream outBuf = (new BufferedOutputStream(new FileOutputStream(
				out)));

		byte[] iv = new byte[16];
		if (encrypt) {
			iv = generateIV();
			outBuf.write(salt);
			outBuf.write(iv);
		} else {
			byte[] saltAndIv = new byte[24];
			inBuf.read(saltAndIv, 0, 24);

			for (int i = 8; i < saltAndIv.length; i++) {
				iv[(i - 8)] = saltAndIv[i];
			}
		}

		EAXBlockCipher eax = new EAXBlockCipher(this.AESCipher);
		CipherParameters cp = new ParametersWithIV(key, iv);
		eax.init(encrypt, cp);

		byte[] bytes = new byte[4096];
		int numRead = 0;
		while ((numRead = inBuf.read(bytes)) >= 0) {
			if (numRead == 4096) {
				byte[] outputTmp = new byte[eax.getUpdateOutputSize(numRead)];
				int written = eax.processBytes(bytes, 0, numRead, outputTmp, 0);
				final byte[] output = new byte[written];
				System.arraycopy(outputTmp, 0, output, 0, output.length);
				outBuf.write(output, 0, output.length);
			} else {
				byte[] outputTmp = new byte[eax.getOutputSize(numRead)];
				int written = eax.processBytes(bytes, 0, numRead, outputTmp, 0);
				written += eax.doFinal(outputTmp, written);
				final byte[] output = new byte[written];
				System.arraycopy(outputTmp, 0, output, 0, output.length);
				outBuf.write(output, 0, output.length);
			}
		}

		outBuf.flush();
		outBuf.close();
		inBuf.close();

	}
}
