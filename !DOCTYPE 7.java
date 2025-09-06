import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.PBEKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Arrays;

public class AES256Encryption {
    
    // Funktion zum Generieren eines sicheren AES-Schlüssels mit PBKDF2
    public static SecretKeySpec generateKey(String password, byte[] salt) throws Exception {
        // Anzahl der Iterationen für PBKDF2
        int iterations = 10000;
        // Länge des Schlüssels (256 Bit = 32 Byte)
        int keyLength = 256;

        // PBKDF2 mit Passwort und Salt
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] key = factory.generateSecret(spec).getEncoded();

        return new SecretKeySpec(key, "AES");
    }

    // Funktion zum Verschlüsseln eines Textes
    public static String encrypt(String text, String password) throws Exception {
        // Generiere ein zufälliges Salt
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        // Generiere den AES-Schlüssel mit PBKDF2 und Salt
        SecretKeySpec key = generateKey(password, salt);

        // Initialisiere den Cipher
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        // Verschlüsseln des Textes
        byte[] encryptedText = cipher.doFinal(text.getBytes());

        // Verkette Salt und verschlüsselten Text, um sie zusammen zu speichern
        byte[] encryptedWithSalt = new byte[salt.length + encryptedText.length];
        System.arraycopy(salt, 0, encryptedWithSalt, 0, salt.length);
        System.arraycopy(encryptedText, 0, encryptedWithSalt, salt.length, encryptedText.length);

        // Rückgabe als Base64-codierten String
        return Base64.getEncoder().encodeToString(encryptedWithSalt);
    }

    // Funktion zum Entschlüsseln eines Textes
    public static String decrypt(String encryptedText, String password) throws Exception {
        // Dekodiere den verschlüsselten Text
        byte[] encryptedWithSalt = Base64.getDecoder().decode(encryptedText);

        // Extrahiere Salt und den verschlüsselten Text
        byte[] salt = Arrays.copyOfRange(encryptedWithSalt, 0, 16);
        byte[] cipherText = Arrays.copyOfRange(encryptedWithSalt, 16, encryptedWithSalt.length);

        // Generiere den AES-Schlüssel mit PBKDF2 und Salt
        SecretKeySpec key = generateKey(password, salt);

        // Initialisiere den Cipher
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);

        // Entschlüsseln des Textes
        byte[] decryptedText = cipher.doFinal(cipherText);

        return new String(decryptedText);
    }

    public static void main(String[] args) {
        try {
            // Beispiel Passwort und Text
            String password = "supersecretespassword";
            String text = "Dies ist ein geheimer Text, der verschlüsselt werden muss!";

            // Verschlüsseln
            String encryptedText = encrypt(text, password);
            System.out.println("Verschlüsselter Text: " + encryptedText);

            // Entschlüsseln
            String decryptedText = decrypt(encryptedText, password);
            System.out.println("Entschlüsselter Text: " + decryptedText);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}