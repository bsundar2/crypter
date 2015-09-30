import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class crypter405 {
	
	// AES-GCM parameters
    public static final int AES_KEY_SIZE = 128; // in bits
    public static final int GCM_NONCE_LENGTH = 12; // in bytes
    public static final int GCM_TAG_LENGTH = 16; // in bytes
	
    public static String readSecretKey() {
		// Copy all this to both functions or make a new function.
		System.out.print("Enter the secret key: ");
		Scanner in = new Scanner(System.in);
		String secretKey = in.nextLine();
		in.close();
		return secretKey;
	}
	
    public static void printErrorMessage() {
		System.out.println("Syntax: \n To Encrypt: ./crypter405 -e <input_file> <ouput_file>"
				+ "\n To Decrypt: ./crypter405 -d <input_file> <ouput_file>");
		System.exit(-1);
	}
	
    public static String getFileData(String mode, String fileName) {
		String input ="";
		try {
			Scanner readInput = new Scanner(new File(fileName));
			while(readInput.hasNextLine()) {
				input += readInput.nextLine();
				if(mode.equals("e"))
					input += "\n";
			}
			readInput.close();
		} catch(FileNotFoundException e) {
			System.out.println("Input file not found.");
			System.exit(-1);
		}
		
		return input;
	}
	
	
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
		
		if(args.length == 3) {
			
			String secretKey = readSecretKey();
	        byte[] byteKey = secretKey.getBytes();
	        SecretKeySpec key = new SecretKeySpec(byteKey, "AES");
	        
	        Cipher cipher = null;
			try {
				cipher = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
			} catch (NoSuchProviderException | NoSuchPaddingException e1) {
				System.out.println("Problem with padding");
				System.exit(-1);
			}
			
	        byte[] nonce = "bsundar2pass".getBytes();
	        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
			
			if(args[0].equals("-e")) {
				// Call function to encrypt.
		        
				String input = getFileData("e", args[1]);
				
				byte[] cipherText = null;
				
				try {
					cipher.init(Cipher.ENCRYPT_MODE, key, spec);
					cipherText = cipher.doFinal(input.getBytes());
				} catch(Exception e) {
					System.out.println("Problem with encrypting data.");
					e.printStackTrace();
					System.exit(-1);
				}
				
				
				try (FileOutputStream fileop = new FileOutputStream(args[2])) {
					fileop.write(cipherText);
				}catch(FileNotFoundException e ) {
					System.out.println("Input file not found.");
					System.exit(-1);
				}
				
	
//				try (Writer writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream("testcipher.txt"), "utf-8"))) {
//					writer.write(secretKey + "\n");
//					writer.write(new String(cipherText, "UTF-8"));
//				} catch(FileNotFoundException UnsupportedEncodingException ) {
//					System.exit(-1);
//				}
				
//				System.out.println("Encrypted data: " + new String(cipherText));
			}
			else if(args[0].equals("-d")) {
				// Call function to decrypt.
				
				byte[] input = null;
				try (DataInputStream datain = new DataInputStream(new FileInputStream(args[1]))) {
					input = new byte[datain.available()];
					datain.readFully(input);
				} catch(IOException e) {
					System.out.println("File not found");
					System.exit(-1);
				}
				
//				String secretKey = readSecretKey();
//				System.out.println("Cipher: " + new String(input));

				byte[] plainText = null;
				try {
					cipher.init(Cipher.DECRYPT_MODE, key, spec);
					plainText = cipher.doFinal(input);
				} catch(Exception e) {
					System.out.println("Problem with decrypting data.");
					e.printStackTrace();
					System.exit(-1);
				}
				
				
				try (Writer writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(args[2]), "utf-8"))) {
					writer.write(new String(plainText, "UTF-8"));
				} catch(FileNotFoundException UnsupportedEncodingException ) {
					System.exit(-1);
				}

//				try (FileOutputStream fileop = new FileOutputStream(args[2])) {
//					fileop.write(plainText);
//				}catch(FileNotFoundException e ) {
//					System.out.println("Input file not found.");
//					System.exit(-1);
//				}
				
				File inputFile = new File(args[2]);
				File tempFile = new File("myTempFile.txt");
				BufferedWriter writer = new BufferedWriter(new FileWriter(tempFile));
				BufferedReader reader = new BufferedReader(new FileReader(inputFile));
				Scanner read = new Scanner(new File(args[2]));
				String currLine;
				while(read.hasNextLine()) {
					currLine = read.nextLine();
					if(read.hasNextLine())
						writer.write(currLine + "\n");
					else
						writer.write(currLine);
				}
				writer.close(); 
				reader.close(); 
				read.close();
				if(inputFile.exists())
					inputFile.delete();
				tempFile.renameTo(inputFile);
				

			}
			else {
				System.out.println("Command not found.");
				printErrorMessage();
			}
			
		}
		else {
			printErrorMessage();
		}

	}
	
	
	
	
	
	
	
	
	/*
	// AES-GCM parameters
    public static final int AES_KEY_SIZE = 128; // in bits
    public static final int GCM_NONCE_LENGTH = 12; // in bytes
    public static final int GCM_TAG_LENGTH = 16; // in bytes
	
	public static String readSecretKey() {
		// Copy all this to both functions or make a new function.
		System.out.print("Enter the secret key: ");
		Scanner in = new Scanner(System.in);
		String secretKey = in.nextLine();
		in.close();
		return secretKey;
	}

	public static void printErrorMessage() {
		System.out.println("Syntax: \n To Encrypt: ./crypter405 -e <input_file> <ouput_file>"
				+ "\n To Decrypt: ./crypter405 -d <input_file> <ouput_file>");
		System.exit(-1);
	}
	
	private static String md5(final String input) throws NoSuchAlgorithmException {
        final MessageDigest md = MessageDigest.getInstance("MD5");
        final byte[] messageDigest = md.digest(input.getBytes());
        final BigInteger number = new BigInteger(1, messageDigest);
        
        return String.format("%032x", number);
    }
	
	private Cipher initCipher(final int mode, final String initialVectorString, final String secretKey)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		final SecretKeySpec skeySpec = new SecretKeySpec(md5(secretKey).getBytes(), "AES");
        final IvParameterSpec initialVector = new IvParameterSpec(initialVectorString.getBytes());
        final Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding");
        cipher.init(mode, skeySpec, initialVector);
        return cipher;
    }
	
	public String encrypt(final String dataToEncrypt, final String initialVector, final String secretKey) {
        String encryptedData = null;
        try {
            // Initialize the cipher
            final Cipher cipher = initCipher(Cipher.ENCRYPT_MODE, initialVector, secretKey);
            // Encrypt the data
            final byte[] encryptedByteArray = cipher.doFinal(dataToEncrypt.getBytes());
            // Encode using Base64
            encryptedData = Base64.getEncoder().encodeToString(encryptedByteArray);
        } catch (Exception e) {
            System.err.println("Problem encrypting the data");
            e.printStackTrace();
            System.exit(-1);
        }
        return encryptedData;
    }
	
	public String decrypt(final String encryptedData, final String initialVector, final String secretKey) {
        String decryptedData = null;
        try {
            // Initialize the cipher
            final Cipher cipher = initCipher(Cipher.DECRYPT_MODE, initialVector, secretKey);
            // Decode using Base64
            final byte[] encryptedByteArray = Base64.getDecoder().decode(encryptedData);
            // Decrypt the data
            final byte[] decryptedByteArray = cipher.doFinal(encryptedByteArray);
            decryptedData = new String(decryptedByteArray, "UTF8");
        } catch (Exception e) {
            System.err.println("Problem decrypting the data");
            e.printStackTrace();
            System.exit(-1);
        }
        return decryptedData;
    }
	
	public static String getFileData(String mode, String fileName) {
		String input ="";
		try {
			Scanner readInput = new Scanner(new File(fileName));
			while(readInput.hasNextLine()) {
				input += readInput.nextLine();
				if(mode.equals("e"))
					input += "\n";
			}
			readInput.close();
		} catch(FileNotFoundException e) {
			System.out.println("Input file not found.");
			System.exit(-1);
		}
		
		return input;
	}
	
	
	public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
		final String iv = "0123456789123456";
		crypter405 crypt = new crypter405();
		
		if(args.length == 3) {
			
			if(args[0].equals("-e")) {
				// Call function to encrypt.
				String input = getFileData("e", args[1]);
				String secretKey = readSecretKey();
				final String encryptedData = crypt.encrypt(input, iv, secretKey);
				
				String cipherHash = md5(encryptedData);
				


		        String last = "";
		        
	
				try (Writer writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream("testcipher.txt"), "utf-8"))) {
//					writer.write(secretKey + "\n");
					writer.write(encryptedData);
				} catch(FileNotFoundException UnsupportedEncodingException ) {
					System.exit(-1);
				}
				
				System.out.println("Encrypted data: " + encryptedData);
			}
			else if(args[0].equals("-d")) {
				// Call function to decrypt.
				String input = getFileData("d", args[1]);
				String secretKey = readSecretKey();
				System.out.println("Cipher: " + input);
				final String decryptedData = crypt.decrypt(input, iv, secretKey);
				
				String validateHash = md5(input);
				

				
				try (Writer writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream("testout.txt"), "utf-8"))) {
					writer.write(decryptedData);
				} catch(FileNotFoundException UnsupportedEncodingException ) {
					System.exit(-1);
				}
				
				System.out.println("Decrypted data: " + decryptedData);
			}
			else {
				System.out.println("Command not found.");
				printErrorMessage();
			}
			
		}
		else {
			printErrorMessage();
		}

	}
*/

	
}
