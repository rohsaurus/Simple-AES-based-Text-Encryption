import org.assertj.core.api.WithAssertions;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;


public class Main {
    private static String unsecuresalt = "12345678";
    private static String cipherText = "";
    private static String plainText = "";
    private static SecretKey key;
    private static String hashed = "";
    private static IvParameterSpec spec;
    private static final String algorithm = "AES/CBC/PKCS5Padding";

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        // write your code here
        while (true) {
            System.out.println("Would you like to create a password or would you like to encrypt/decrypt a program.\nEnter 1 to create a password\nEnter 2 to encrypt\nEnter 3 to decrypt");
            Scanner in = new Scanner(System.in);
            int choice = in.nextInt();
            if (choice == 1) {
                System.out.println("Enter in your password that you want to use");
                String dump = in.nextLine();
                String user = in.nextLine();
                // need to implement secure salt
                spec = AES.generateIv();
                key = AES.getKeyFromPassword(user, unsecuresalt);
                hashed = BCrypt.hashpw(user,BCrypt.gensalt());
            }

            else if (choice == 2) {
                System.out.println("Enter in your password");
                String dump = in.nextLine();
                String pass = in.nextLine();
                int i = 1;
                while (i!=0) {
                    if (BCrypt.checkpw(pass, hashed)) {
                        Scanner newLol = new Scanner(System.in);
                        System.out.println("Enter the text you would like to be ciphered.");
                        plainText = newLol.nextLine();
                        cipherText = AES.encryptPasswordBased(plainText, key, spec);
                        System.out.println("Encrypted Text:\n" + cipherText);
                        i = 0;
                    }
                    else {
                        System.out.println("Your password is wrong. Please enter it again.");
                        Scanner funnyDump = new Scanner (System.in);
                        pass = funnyDump.nextLine();
                    }
                }

            } else if (choice == 3) {
                System.out.println("Enter in your password");
                String dump = in.nextLine();
                String pass = in.nextLine();
                int i = 1;
                while(i!=0) {
                    if (BCrypt.checkpw(pass, hashed)) {
                        System.out.println("Enter cipherText:");
                        Scanner abc = new Scanner(System.in);
                        cipherText = abc.nextLine();
                        String decryptedCipherText = AES.decryptPasswordBased(cipherText, key, spec);
                        System.out.println("Decrypted text:\n" + decryptedCipherText);
                        i = 0;
                        // Assertions to check if equal to
                        // Assertions.assertEquals(plainText, decryptedCipherText);
                    } else {
                        System.out.println("Your password is wrong. Please enter it again.");
                        Scanner funnyDump = new Scanner(System.in);
                        pass = funnyDump.nextLine();
                    }
                }
            }
            /*else if (choice == 3) {
                System.out.println("Would you like to decrypt your previously encrypted text, or would you like to decrypt a different text? Enter 1 for same and 2 for different.");
                String dumpTime = in.nextLine();
                int userChoice = in.nextInt();
                if (userChoice == 2) {
                    System.out.println("Enter the encrypted text you want to decrypt.");
                    String dumpytown = in.nextLine();
                    String temp = in.nextLine();
                    cipherd = temp;
                }

                plainText = AES.decryptPasswordBased(algorithm, cipherd, funnyKey, spec);
                System.out.println("Decrypted text:\n" + plainText);
                */
             else {
                System.out.println("Exiting Program");
                System.exit(1);
            }
        }
    }
    }