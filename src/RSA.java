import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * @author lakinduakash
 *         Created by lakinduakash on 1/17/18.
 */

public class RSA
{
    public final static String ALGORITHM = "RSA";


    public static KeyPair genKeyPair(int keySize) throws NoSuchAlgorithmException
    {
        KeyPair keyPair;
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        keyGen.initialize(keySize);
        keyPair = keyGen.generateKeyPair();


        return keyPair;
    }

    public static byte[] encrypt(PublicKey pKey, byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {
        byte[] encryptedData;

        final Cipher cipher = Cipher.getInstance(ALGORITHM);

        cipher.init(Cipher.ENCRYPT_MODE, pKey);
        encryptedData = cipher.doFinal(data);

        return encryptedData;
    }

    public static byte[] decrypt(PrivateKey privateKey, byte[] encryptedData) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException
    {
        byte[] decryptedData;
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        decryptedData = cipher.doFinal(encryptedData);

        return decryptedData;
    }

    public static String getEncryptedBase64String(PublicKey publicKey, String base64String) throws NoSuchAlgorithmException, NoSuchPaddingException,
            IllegalBlockSizeException, InvalidKeyException, BadPaddingException
    {
        byte[] rawBytes = Base64.getDecoder().decode(base64String);
        byte[] encryptedBytes = encrypt(publicKey, rawBytes);

        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String getEncryptedBase64String(PublicKey publicKey, byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException,
            IllegalBlockSizeException, InvalidKeyException, BadPaddingException
    {
        byte[] encryptedBytes = encrypt(publicKey, data);

        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String getPublicKeyAsBase64Encoded(PublicKey publicKey)
    {
        return Base64.getEncoder().encodeToString(getPublicKeyBytes(publicKey));
    }

    private static byte[] getPublicKeyBytes(PublicKey publicKey)
    {
        return publicKey.getEncoded();
    }

    public static PublicKey getPublicKey(byte[] X509EncodedData) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(X509EncodedData);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        return keyFactory.generatePublic(x509EncodedKeySpec);

    }

    public static String getAlgorithm()
    {
        return ALGORITHM;
    }


}
