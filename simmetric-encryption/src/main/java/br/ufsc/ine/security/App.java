package br.ufsc.ine.security;

import java.util.Scanner;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@SuppressWarnings("unused")
public class App {
	
	private static Logger logger = LogManager.getLogger();

	public static void main(String[] args) {
		//responderCifrarDecifrar();
		//responderDescobrirTexto();
		//calculaHash();
		//calculaHMac();
		cryptoAuthPBKDF2();

	}

	private static void cryptoAuthPBKDF2() {
		String plainTxt;
		String pass;
		
		try (Scanner input = new Scanner(System.in)) {
			System.out.println("Digite a msg: ");
			plainTxt = input.nextLine();
			System.out.println("Digite a senha: ");
			pass = input.nextLine();
			System.out.println("Plain text : ");
			System.out.println(plainTxt);
			
		}
		
	}

	private static void calculaHMac() {
		MacCalculator calculator = new MacCalculator();
		String plainTxt;
		String pass;
		try (Scanner input = new Scanner(System.in)) {
			System.out.println("Digite a msg: ");
			plainTxt = input.nextLine();
			System.out.println("Digite a senha: ");
			pass = input.nextLine();
			System.out.println("Plain text : ");
			System.out.println(plainTxt);
			System.out.println("Encoded text : ");
			System.out.println(calculator.getMac(plainTxt, pass));
			System.out.println("Encoded text (second execution with same input) : ");
			System.out.println(calculator.getMac(plainTxt, pass));
		}
	}

	private static void calculaHash() {
		final String text1 = "resultado";
		final String text2 = "resultado2";
		HashCalculator calculator = new HashCalculator();
		System.out.println("Resultado do calculo para o mesmo texto:\t");
		System.out.println(calculator.getHash(text1));
		System.out.println(calculator.getHash(text1));
		System.out.println("\n");
		System.out.println("Resultado do calculo para textos diferentes:\t");
		System.out.println(calculator.getHash(text1));
		System.out.println(calculator.getHash(text2));
	}

	private static void responderDescobrirTexto() {
		final String aesKeyCbc = "61db043f03148b11ac184af2c33a7659";
		final String chiperMessage1 = "2f70627169811ad3732352be6ce82132c373d66f593332592ce1d4802296813932828bc4511d32e6ff15ccb55fb3436c27d8856520f5f212d9a6efe1c8";

		final String aesKeyCtr = "64e904151b40021bb0cef5eaa0e37c22";
		final String chiperMessage2 = "b5a03f98b9fbacc438f038d1ebf446ad40dafd29b0f80dbe79e2efb52b77fe62ee1bc6f41eb32a6a106c3e5abcd3becb38839b0c88839e7319b6368846e51b96db3d2211cf9b5280b0cef52111a5bb6479e1c0";
		
		try {
			ProjetoAesEncontraTexto aesCbc = new ProjetoAesEncontraTexto("AES/CBC/PKCS5Padding", aesKeyCbc);
			String decrypt1 = aesCbc.decrypt(chiperMessage1);
			System.out.println(decrypt1);
			
		} catch (Exception e) {
			logger.error("Error find hidden text with block mode.", e);
		}
		
		try {
			ProjetoAesEncontraTexto aesCtr = new ProjetoAesEncontraTexto("AES/CTR/NoPadding", aesKeyCtr);
			String decrypt2 = aesCtr.decrypt(chiperMessage2);
			System.out.println(decrypt2);
			
		}catch (Exception e) {
			logger.error("Error find hidden text with counter mode.", e);
		}
		

	}

	private static void responderCifrarDecifrar() {
		ProjetoAesEntraDados obj = new ProjetoAesEntraDados();

		String paraCifrar;

		try (Scanner input = new Scanner(System.in)) {
			System.out.println("Digite a msg para cifrar: ");
			paraCifrar = input.nextLine();

			System.out.println("Mensagem original = " + paraCifrar);
			String cifrada = obj.encrypt(paraCifrar);
			System.out.println("Mensagem cifrada = " + cifrada);
			String decifrada = null;
			decifrada = obj.decrypt(cifrada);
			System.out.println("Mensagem decifrada = " + decifrada);
		}
	}

}
