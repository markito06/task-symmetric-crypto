package br.ufsc.ine.security;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import org.apache.commons.codec.DecoderException;
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
}
