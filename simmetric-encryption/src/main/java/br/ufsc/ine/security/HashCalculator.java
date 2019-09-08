package br.ufsc.ine.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;

public class HashCalculator {

	private static Logger logger = LogManager.getLogger();
	public String getHash(final String input) {
		String result = null;
		try {
			final MessageDigest sha3256 = MessageDigest.getInstance("SHA3-256");
			
			byte[] digest = sha3256.digest(input.getBytes(StandardCharsets.UTF_8));
			
			result = Hex.toHexString(digest); 
			
			
		} catch (Exception e) {
			logger.error("Error on calculate hash from some text.", e);
		}
		return result;
	}
}
