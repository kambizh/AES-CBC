import javax.crypto.KeyGenerator;
import javax.crypto.Cipher
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;
     
int AES_KEY_BIT = 256;
int IV_LENGTH_BYTE = 12;
byte[] iv = getRandomNonce(IV_LENGTH_BYTE);
SecretKey key = getAESKey(AES_KEY_BIT);

println("KEY : " + key)
println("IV  : " + iv)
def plainText = "myPassword" 
def encryptedPassword = encrypt(plainText.getBytes(), key, iv);
println("Encrypted Password : " + encryptedPassword.encodeHex().toString())

def decryptedpassword = decrypt(encryptedPassword, key, iv)
println("Decrypted Password : " + decryptedpassword)      


public static SecretKey getAESKey(int keysize) {
    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    keyGen.init(keysize, SecureRandom.getInstanceStrong());
    return keyGen.generateKey();
}

public static byte[] getRandomNonce(int numBytes) {
    byte[] nonce = new byte[numBytes];
    new SecureRandom().nextBytes(nonce);
    return nonce;
}
 
public static String decrypt(byte[] cText, SecretKey secret, byte[] iv) throws Exception {

String ENCRYPT_ALGO = "AES/GCM/NoPadding";
int TAG_LENGTH_BIT = 128;
int IV_LENGTH_BYTE = 12;
int AES_KEY_BIT = 256;


   Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
    cipher.init(Cipher.DECRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
    byte[] plainText = cipher.doFinal(cText);
    return new String(plainText);

}


public static byte[] encrypt(byte[] pText, SecretKey secret, byte[] iv) throws Exception {

String ENCRYPT_ALGO = "AES/GCM/NoPadding";
int TAG_LENGTH_BIT = 128;
int IV_LENGTH_BYTE = 12;
int AES_KEY_BIT = 256;
   Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
   cipher.init(Cipher.ENCRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
   byte[] encryptedText = cipher.doFinal(pText);
   return encryptedText;

}


