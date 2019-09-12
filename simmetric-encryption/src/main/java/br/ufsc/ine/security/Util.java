package br.ufsc.ine.security;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Util {

	private static final Logger logger = LogManager.getLogger();
	
	public static byte[] getKey() {
		byte [] result = {};
		try {
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
			result = new byte[16];
			random.nextBytes(result);
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			logger.error("Error generating random key.",e);
		}
		
		return result;
	}

	public static byte[] getKey(String pass) throws DecoderException {
		 
		return pass.getBytes();
	}
	
	public static String getKeyPbkdf( String password, String salt, Integer iterations) {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), iterations, 256);
        SecretKeyFactory pbkdf2 = null;
        String derivedPass = null;
        try {
            pbkdf2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            SecretKey sk = pbkdf2.generateSecret(spec);
            derivedPass = Hex.encodeHexString(sk.getEncoded());
        } catch (Exception e) {
        	logger.error("Error generating random pbkdfkey.",e);
        }
        return derivedPass;
    }
	
	public static String getSalt() {
        SecureRandom sr;
        byte []  salt = {};
		try {
			sr = SecureRandom.getInstance("SHA1PRNG");
			salt = new byte[16];
			sr.nextBytes(salt);
		} catch (NoSuchAlgorithmException e) {
			logger.error("Error get salt.",e);
		}
        return Hex.encodeHexString(salt);
    }
}
