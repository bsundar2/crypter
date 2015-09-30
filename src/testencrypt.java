import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


/**
 * This class provides methods to encrypt and decrypt data.
 * @author Stephane Moreau
 */
public class testencrypt {

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
        }
        return decryptedData;
    }

    public static void main(final String[] args) throws NoSuchAlgorithmException {
        final String iv = "0123456789123456"; // This has to be 16 characters
        final String secretKey = "passwordpassword";
        final testencrypt crypto = new testencrypt();
        final String input = "This is a test message.";
        final String origHash = md5(input);
        
        final String encryptedData = crypto.encrypt(input, iv, secretKey);
        String hash = md5(encryptedData);
        
        // System.out.println("Original: " + origHash);
        System.out.println("Hash: " + hash);
        
        if(origHash.compareTo(hash) == 0)
        	System.out.println("Success!");
     
        // System.out.println(encryptedData);

        String hashAgain = md5("dJp4akc/vAc5f0S2kncRkV/ZCT1NKaM=");
        System.out.println("Hash Again: " + hashAgain);
        
        final String decryptedData = crypto.decrypt("dJp4akc/vAc5f0S2kncRkV/ZCT1NKaM=", iv, secretKey);
        System.out.println(decryptedData);
    }
}