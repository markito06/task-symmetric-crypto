package br.ufsc.ine.security;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.codec.binary.Hex;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CryptoAuth {

	private Key aesKey;
	private byte iv[];
	private IvParameterSpec ivSpec;
	private Cipher cipher;
	private static Logger logger = LogManager.getLogger();
	
	public String encrypt(String strToEncrypt) {
		try {
			cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);

			final String encryptedString = Hex.encodeHexString(cipher.doFinal(strToEncrypt.getBytes()));
			return encryptedString;

		} catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException
				| BadPaddingException e) {
			logger.error("Error in encrypt", e);
		}
		return null;
	}
	
	public void init() {
		try {
			System.out.println("Setting cipher.");
			cipher = Cipher.getInstance("AES/GCM/NoPadding");

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
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException e) {
			logger.error("Error ", e);
		}
	}
}
