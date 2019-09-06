package br.ufsc.ine.security;

import java.util.Scanner;

public class App {
	public static void main(String[] args) {
		//responderCifrarDecifrar();
		responderDescobrirTexto();

	}

	private static void responderDescobrirTexto() {
		String chaveCBC = "61db043f03148b11ac184af2c33a7659";
		String ivAndTexto = "2f70627169811ad3732352be6ce82132c373d66f593332592ce1d4802296813932828bc"
				+ "4511d32e6ff15ccb55fb3436c27d8856520f5f212d9a6efe1c8";
		ProjetoAesEncontraTexto aesCbc = new ProjetoAesEncontraTexto("AES/CBC/PKCS5Padding", chaveCBC);
		String decrypt = aesCbc.decrypt(ivAndTexto);
		System.out.println(decrypt);
		
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
