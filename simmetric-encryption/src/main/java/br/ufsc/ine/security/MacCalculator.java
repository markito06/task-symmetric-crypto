package br.ufsc.ine.security;

import java.security.Key;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class MacCalculator {

	private static Logger logger = LogManager.getLogger();
	
	public String getMac(final String input, String pass) {
		String result = null;
		try {
			byte[] random = Util.getKey(pass); 
			Mac hMac = Mac.getInstance("HmacSHA384");
			Key hMacKey = new SecretKeySpec(random, "HmacSHA384");
			hMac.init(hMacKey);
			byte[] b = hMac.doFinal(input.getBytes());
			result = new String(Hex.encodeHex(b));
		} catch (Exception e) {
			logger.error("Error in generate hmac", e);
		}
		
		return result;
	}
}
