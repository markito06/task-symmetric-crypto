package br.ufsc.ine.security;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

public class ProjetoAesEncontraTexto {

	private Key aesKey;
	private Cipher cipher;
	private static Logger logger = Logger.getLogger(ProjetoAesEncontraTexto.class.getName());

	public ProjetoAesEncontraTexto(String algAndMode, String key) {
		logger.info("Setup chiper in mode : " + algAndMode);

		try {
			cipher = Cipher.getInstance(algAndMode);
			byte[] encodedKey = Hex.decodeHex(key.toCharArray());
			SecretKey originalKey = new SecretKeySpec(encodedKey, "AES");
			this.aesKey = originalKey;
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | DecoderException e) {
			logger.log(Level.SEVERE, "Error in setup.", e);
		}

		logger.info("End of setup.");

	}

	public String decrypt(String dec) {
		try {
			
			IvParameterSpec  ivParameterSpec =  new IvParameterSpec(extractIv(dec));
			cipher.init(Cipher.DECRYPT_MODE, aesKey, ivParameterSpec);
			String decryptedString = new String(cipher.doFinal(extractTexto(dec)));
			return decryptedString;

		} catch (IllegalBlockSizeException | BadPaddingException |  InvalidKeyException
				| InvalidAlgorithmParameterException e) {
			logger.log(Level.SEVERE, "Error in decrypt chiper text.", e);
		}
		return null;
	}

	private byte[] extractTexto(String dec) {
		String textPart = dec.substring(32);
		byte[] text = {};
		try {
		text = Hex.decodeHex(textPart.toCharArray());
		} catch (DecoderException e) {
			logger.log(Level.SEVERE, "Error on extract text.", e);
		}
		return text;
	}

	private byte[] extractIv(String dec) {
 		String ivPart = dec.substring(0,32);
		System.out.println(ivPart);
		byte[] iv = {}; 
		try {
			iv = Hex.decodeHex(ivPart.toCharArray());
		} catch (DecoderException e) {
			logger.log(Level.SEVERE, "Error on extract iv.", e);
		}
		return iv;
	}

}
