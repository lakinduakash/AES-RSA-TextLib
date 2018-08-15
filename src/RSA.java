/*
Copyright 2018 Lakindu Akash

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */

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
 * This class is based more on handling string data rather than raw data. However there are functions for raw data
 * as helper functions.
 *
 */


public class RSA
{
    //Using RSA algorithm
    public final static String ALGORITHM = "RSA";


    /**
     * Generate KeyPair object to given key size in bit length.
     * @param keySize length of key size. 2048,1024 etc.
     * @return randomly generated KeyPair object
     * @throws NoSuchAlgorithmException
     */
    public static KeyPair genKeyPair(int keySize) throws NoSuchAlgorithmException
    {
        KeyPair keyPair;
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        keyGen.initialize(keySize);
        keyPair = keyGen.generateKeyPair();


        return keyPair;
    }

    /**
     * Encrypt raw byte array using a given public key
     * @param pKey public key for encrypt
     * @param data data to encrypt as byte array
     * @return encrypted data array
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static byte[] encrypt(PublicKey pKey, byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {
        byte[] encryptedData;

        final Cipher cipher = Cipher.getInstance(ALGORITHM);

        cipher.init(Cipher.ENCRYPT_MODE, pKey);
        encryptedData = cipher.doFinal(data);

        return encryptedData;
    }

    /**
     * Decrypt raw data using private key
     * @param privateKey private key to use
     * @param encryptedData data to decrypt as byte array
     * @return decrypted data
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static byte[] decrypt(PrivateKey privateKey, byte[] encryptedData) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException
    {
        byte[] decryptedData;
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        decryptedData = cipher.doFinal(encryptedData);

        return decryptedData;
    }


    public static String getDecryptedDataBASE64(PrivateKey privateKey, String encryptedDataBASE64) {

        return null;
    }

    /**
     * This function encrypt data form of BASE64 string and return encrypted data as BASE64 string
     * @param publicKey public key for encrypting
     * @param base64String data as BASE64 string
     * @return encrypted data as BASE64 string
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalArgumentException if given string is not a valid BASE64 string
     */
    public static String getEncryptedBase64String(PublicKey publicKey, String base64String) throws NoSuchAlgorithmException, NoSuchPaddingException,
            IllegalBlockSizeException, InvalidKeyException, BadPaddingException
    {
        byte[] rawBytes = Base64.getDecoder().decode(base64String);
        byte[] encryptedBytes = encrypt(publicKey, rawBytes);

        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    /**
     * Encrypt raw data and return encrypted data as BASE64 string
     * @param publicKey public key for encrypting
     * @param data data to encrypt as byte array
     * @return encrypted data as BASE64 string
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     */
    public static String getEncryptedBase64String(PublicKey publicKey, byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException,
            IllegalBlockSizeException, InvalidKeyException, BadPaddingException
    {
        byte[] encryptedBytes = encrypt(publicKey, data);

        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    /**
     * Get public key as BASE64 string
     * @param publicKey PublicKey to encode
     * @return encoded public key as BASE64 string
     */
    public static String getPublicKeyAsBase64Encoded(PublicKey publicKey)
    {
        return Base64.getEncoder().encodeToString(getPublicKeyBytes(publicKey));
    }

    /**
     * Convert public key to byte array
     * @param publicKey PublicKey to convert
     * @return byte array of public key
     */
    private static byte[] getPublicKeyBytes(PublicKey publicKey)
    {
        return publicKey.getEncoded();
    }

    /**
     * Get public key from X509 encoded data. This might help to retrive public key file from disk.
     * @param X509EncodedData byte array of data. format should be X509 encoded
     * @return PublicKey object
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException if data array has not valid X509 data
     */
    public static PublicKey getPublicKey(byte[] X509EncodedData) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(X509EncodedData);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        return keyFactory.generatePublic(x509EncodedKeySpec);

    }

    /**
     * Return the algorithm
     * @return algorithm
     */
    public static String getAlgorithm()
    {
        return ALGORITHM;
    }


}
