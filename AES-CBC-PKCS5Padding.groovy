import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.crypto.Cipher


def iv = "1234567890123456"
def key = iv
println("KEY : " + key)
println("IV  : " + iv)
def plainText = "myPassword" 
def encryptedPassword = encrypt(plainText, key, iv)
println("Encrypted Password : " + encryptedPassword)
def decryptedpassword = decrypt(encryptedPassword, key, iv)
println("Decrypted Password : " + decryptedpassword)      

 
    public static decrypt(String encrypted, key, iv) {
        if (encrypted) {
            byte[] encryptedByte = encrypted.decodeHex()
            byte[] keyByte = key
            byte[] ivByte = iv
            SecretKeySpec sKeySpec = new SecretKeySpec(keyByte, "AES")
            IvParameterSpec ivSpec = new IvParameterSpec(ivByte)
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding")
            c.init(Cipher.DECRYPT_MODE, sKeySpec, ivSpec)
            byte[] decrypted = c.doFinal(encryptedByte)
            return new String(decrypted)
        }
        else {
            return encrypted
        }
    }

    public static encrypt(String plainText, key, iv) {
        if (plainText) {
            SecretKeySpec sKeySpec = new SecretKeySpec(key.getBytes(), "AES")
            IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes())
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding")
            c.init(Cipher.ENCRYPT_MODE, sKeySpec, ivSpec)
            byte[] encryptedPassword = c.doFinal(plainText.getBytes())
            return encryptedPassword.encodeHex().toString()
        }
        else {
            return plainText
        }
    }


