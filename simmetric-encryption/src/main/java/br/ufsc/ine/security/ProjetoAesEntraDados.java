package br.ufsc.ine.security;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

public class ProjetoAesEntraDados {

	private Key aesKey;
	private byte iv[];
	private IvParameterSpec ivSpec;
	private Cipher cipher;
	private static Logger logger = Logger.getLogger(ProjetoAesEntraDados.class.getName());
	

	public ProjetoAesEntraDados() {
		try {
			logger.info("Configurando cifrador");
			cipher = Cipher.getInstance("AES/CTR/NoPadding");

			// Gera uma chave AES
			System.out.print("Gerando chave \t-> ");
			KeyGenerator sKenGen = KeyGenerator.getInstance("AES");
			aesKey = sKenGen.generateKey();
			System.out.println("Chave AES \t= " + Hex.encodeHexString(aesKey.getEncoded()));

			// Gerando o iv com SecureRandom
			System.out.print("Gerando IV \t-> ");
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
			iv = new byte[16];
			random.nextBytes(iv);
			ivSpec = new IvParameterSpec(iv);
			System.out.println("IV \t= " + Hex.encodeHexString(iv));
			logger.info("Fim da configuração");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException e) {
			logger.log(Level.SEVERE, null, e);
		}

	}

	public String encrypt(String strToEncrypt) {
		try {
			cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);

			final String encryptedString = Hex.encodeHexString(cipher.doFinal(strToEncrypt.getBytes()));
			return encryptedString;

		} catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException
				| BadPaddingException e) {
			logger.log(Level.SEVERE, null, e);
		}
		return null;
	}

	public String decrypt(String dec) {
		try {
			cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
			byte[] embytes = {};
			embytes = Hex.decodeHex(dec.toCharArray());

			String decryptedString = new String(cipher.doFinal(embytes));

			return decryptedString;

		} catch (IllegalBlockSizeException | BadPaddingException | DecoderException | InvalidKeyException | InvalidAlgorithmParameterException e) {
			logger.log(Level.SEVERE, null, e);
		}
		return null;
	}

}
