import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Random;

import org.spongycastle.crypto.BlockCipher;
import org.spongycastle.crypto.BufferedBlockCipher;
import org.spongycastle.crypto.CipherParameters;
import org.spongycastle.crypto.DataLengthException;
import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.engines.AESEngine;
import org.spongycastle.crypto.io.CipherInputStream;
import org.spongycastle.crypto.io.CipherOutputStream;
import org.spongycastle.crypto.modes.CBCBlockCipher;
import org.spongycastle.crypto.paddings.BlockCipherPadding;
import org.spongycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;

public class AESModeCBC {
	private final BlockCipher AESCipher = new AESEngine();
	private BufferedBlockCipher pBuffer;
	private BlockCipherPadding padding;
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

	public void setPadding(BlockCipherPadding padding) {
		this.padding = padding;
	}

	public void encrypt(File in, File out) throws DataLengthException,
			InvalidCipherTextException, IOException {
		processing(in, out, true);
	}

	public void decrypt(File in, File out) throws DataLengthException,
			InvalidCipherTextException, IOException {
		processing(in, out, false);
	}

	public void processing(File in, File out, boolean encrypt)
			throws DataLengthException, InvalidCipherTextException, IOException {

		InputStream rBuffer = (new BufferedInputStream(new FileInputStream(in)));

		OutputStream wBuffer = (new BufferedOutputStream(new FileOutputStream(
				out)));

		byte[] iv = new byte[16];
		if (encrypt) {
			iv = generateIV();
			wBuffer.write(salt);
			wBuffer.write(iv);
		} else {
			byte[] saltAndIv = new byte[24];
			rBuffer.read(saltAndIv, 0, 24);

			for (int i = 8; i < saltAndIv.length; i++) {
				iv[(i - 8)] = saltAndIv[i];
			}
		}

		pBuffer = new PaddedBufferedBlockCipher(new CBCBlockCipher(AESCipher),
				padding);
		CipherParameters cp = new ParametersWithIV(key, iv);
		pBuffer.init(encrypt, cp);

		if (encrypt)
			wBuffer = new CipherOutputStream(wBuffer, pBuffer);
		else
			rBuffer = new CipherInputStream(rBuffer, pBuffer);

		byte[] bytes = new byte[4096];

		int numRead = 0;
		while ((numRead = rBuffer.read(bytes)) >= 0)
			wBuffer.write(bytes, 0, numRead);

		wBuffer.flush();
		wBuffer.close();
		rBuffer.close();
	}

	public void restAES() {
		AESCipher.reset();
	}

}
