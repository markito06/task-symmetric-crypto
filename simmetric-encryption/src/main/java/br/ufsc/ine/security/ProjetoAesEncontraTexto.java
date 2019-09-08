package br.ufsc.ine.security;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ProjetoAesEncontraTexto {

	private Key aesKey;
	private Cipher cipher;
	private static Logger logger = LogManager.getLogger();

	/**
	 * Constructor and setter of cipher
	 **/
	public ProjetoAesEncontraTexto(String algAndMode, String key) {
		System.out.println("Setting cipher in mode : " + algAndMode);

		try {
			cipher = Cipher.getInstance(algAndMode);
			byte[] encodedKey = Hex.decodeHex(key.toCharArray());
			SecretKey originalKey = new SecretKeySpec(encodedKey, "AES");
			this.aesKey = originalKey;
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | DecoderException e) {
			logger.error("Error in setup chiper in mode : {}.",algAndMode, e);
		}

	}

	/**
	 * Decrypt the ciphertext send
	 **/
	public String decrypt(String dec) {
		try {

			cipher.init(Cipher.DECRYPT_MODE, aesKey, extractIv(dec));
			String hiddenMessage = new String(cipher.doFinal(extractChiperMessage(dec)), StandardCharsets.UTF_8);
			return hiddenMessage;

		} catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException
				| InvalidAlgorithmParameterException e) {
			logger.error("Error in decrypt chiper text.", e);
		}
		return null;
	}

	/**
	 * Extract part representing encrypted message
	 */
	private byte[] extractChiperMessage(String dec) {
		String textPart = dec.substring(32);
		System.out.println("msg:{" + textPart + "} - length : " + textPart.length());
		byte[] text = {};
		try {
			text = Hex.decodeHex(textPart.toCharArray());
		} catch (DecoderException e) {
			logger.error( "Error on extract text.", e);
		}
		return text;
	}

	/**
	 * Extract part of concatenated text at beginning of encrypted message
	 */
	private IvParameterSpec extractIv(String dec) {
		String ivPart = dec.substring(0, 32);
		System.out.println("iv:{" + ivPart + "} - lenth : " + ivPart.length());
		byte[] iv = {};
		try {
			iv = Hex.decodeHex(ivPart.toCharArray());
		} catch (DecoderException e) {
			logger.error("Error on extract iv.", e);
		}
		return new IvParameterSpec(iv);
	}

}
