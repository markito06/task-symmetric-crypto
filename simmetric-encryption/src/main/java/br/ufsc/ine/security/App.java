package br.ufsc.ine.security;

import java.util.Scanner;

public class App {
	public static void main(String[] args) {
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
