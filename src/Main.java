import org.assertj.core.api.WithAssertions;
import org.checkerframework.checker.units.qual.A;
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
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Scanner;
import javax.swing.filechooser.*;


public class Main {
    private static final String unsecuresalt = "12345678";
    private static String cipherText = "";
    private static String plainText = "";
    private static SecretKey key;
    private static String hashed = "";
    private static IvParameterSpec spec;
    private static final String algorithm = "AES/CBC/PKCS5Padding";
    private static ArrayList <String> cipherBoys = new ArrayList<String>();
    private static final File inputFile = Paths.get("src/tutorials.md").toFile();
    private static final File encryptedFile = new File("classpath:brugger.encrypted");
    private static final File decryptedFile = new File("document.decrypted");


    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException {
        // write your code here
        while (true) {
            System.out.println("Would you like to create a password or would you like to encrypt/decrypt a program.\nEnter 1 to create a password\nEnter 2 to encrypt text\nEnter 3 to decrypt text\nEnter 4 to encrypt a file\nEnter 5 to decrypt a file.");
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
                        cipherBoys.add(cipherText);
                        System.out.println("Encrypted Text:\n" + cipherText);
                        System.out.println("Message ID #: " + cipherBoys.size());
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
                        System.out.println("Enter Message ID #:");
                        Scanner abc = new Scanner(System.in);
                        int id = abc.nextInt();
                        cipherText = cipherBoys.get(id-1);
                        String decryptedCipherText = AES.decryptPasswordBased(cipherText, key, spec);
                        System.out.println("Decrypted text:\n" + decryptedCipherText);
                        i = 0;
                    } else {
                        System.out.println("Your password is wrong. Please enter it again.");
                        Scanner funnyDump = new Scanner(System.in);
                        pass = funnyDump.nextLine();
                    }
                }
            }
            else if (choice == 4) {
                int i = 1;
                System.out.println("Enter in your password:");
                Scanner dumpMoment = new Scanner(System.in);
                String pass = dumpMoment.nextLine();
                while (i!=0) {
                    if (BCrypt.checkpw(pass,hashed)) {
                        AES.encryptFile(algorithm, key, spec, inputFile, encryptedFile);
                    }
                    else {
                        System.out.println("Your password is wrong. Please enter it again.");
                        Scanner funnyDump = new Scanner(System.in);
                        pass = funnyDump.nextLine();
                    }
                }

            }
            else if (choice == 5) {
                System.out.println("Enter in your password:");
                int i = 1;
                Scanner dumpMoment = new Scanner(System.in);
                String pass = dumpMoment.nextLine();
                while (i!=0) {
                    if (BCrypt.checkpw(pass,hashed)){
                        AES.decryptFile(algorithm, key, spec, encryptedFile, decryptedFile);
                    }
                    else {
                        System.out.println("Your password is wrong. Please enter it again.");
                        Scanner funnyDump = new Scanner(System.in);
                        pass = funnyDump.nextLine();
                    }
                }
            }
             else {
                System.out.println("Exiting Program");
                System.exit(1);
            }
        }
    }
    }