package com.ultimatex.textcrypto;/*
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

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * @author lakinduakash
 * Created by lakinduakash on 1/17/18.
 */
public class AES
{
    public static final String ALGORITHM="AES";

    /**
     * Generate secret key object from given key size in bit length.
     * @param keySize length of key size. 128, 256 etc.
     * @return randomly generated secret key object
     */
    public static SecretKey genKey(int keySize)
    {
        SecretKey key=null;
        try
        {
            KeyGenerator keyGenerator= KeyGenerator.getInstance(ALGORITHM);
            keyGenerator.init(keySize);
            key =keyGenerator.generateKey();

        } catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        }

        return key;
    }

    /**
     * Encrypt raw byte array using a given secret key
     * @param key public key for encrypt
     * @param data data to encrypt as byte array
     * @return encrypted data array
     * @throws InvalidKeyException if public key is invalid
     * @throws IllegalBlockSizeException if data is not valid
     * @throws BadPaddingException if data is not valid
     */
    public static byte[] encrypt(SecretKey key,byte[] data) throws InvalidKeyException,IllegalBlockSizeException,
            BadPaddingException
    {
        byte[] encriptedData=null;
        try
        {
            Cipher cipher=Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE,key);
            encriptedData= cipher.doFinal(data);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException e)
        {
            e.printStackTrace();
        }
        return encriptedData;
    }


    /**
     * Encrypt raw data and return encrypted data as BASE64 string
     *
     * @param key  secret key for encrypting
     * @param data data to encrypt as byte array
     * @return encrypted data as BASE64 string
     * @throws InvalidKeyException if public key is invalid
     * @throws IllegalBlockSizeException if data is not valid
     * @throws BadPaddingException if data is not valid
     */
    public static String getEncryptedDataBase64(SecretKey key, byte[] data) throws BadPaddingException,IllegalBlockSizeException,
            InvalidKeyException {
        return Base64.getEncoder().encodeToString(encrypt(key,data));
    }

    /**
     * This function encrypt data form of BASE64 string and return encrypted data as BASE64 string
     *
     * @param key                 secret key for encrypting
     * @param base64EncodedString data as BASE64 string
     * @return encrypted data as BASE64 string
     * @throws InvalidKeyException if public key is invalid
     * @throws IllegalBlockSizeException if data is not valid
     * @throws BadPaddingException if data is not valid
     * @throws IllegalArgumentException  if given string is not a valid BASE64 string
     */
    public static String getEncryptedDataBase64(SecretKey key, String base64EncodedString) throws BadPaddingException,IllegalBlockSizeException,
            InvalidKeyException {
        return Base64.getEncoder().encodeToString(encrypt(key,Base64.getDecoder().decode(base64EncodedString)));
    }

    /**
     * Decrypt raw data using AES secret key
     *
     * @param key           secret key to use
     * @param encryptedData data to decrypt as byte array
     * @return decrypted data
     * @throws InvalidKeyException if public key is invalid
     * @throws IllegalBlockSizeException if data is not valid
     * @throws BadPaddingException if data is not valid
     */
    public static byte[] decrypt(SecretKey key, byte[] encryptedData) throws BadPaddingException,IllegalBlockSizeException,
            InvalidKeyException {
        byte[] decryptedData=null;

        try {
            Cipher cipher =Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE,key);
            decryptedData = cipher.doFinal(encryptedData);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }

        return decryptedData;
    }

    /**
     * Get decrypted data as BASE64 string.
     *
     * @param key  secret key to decrypt
     * @param data byte array of encrypted data
     * @return decrypted data as BASE64 string
     * @throws InvalidKeyException if public key is invalid
     * @throws IllegalBlockSizeException if data is not valid
     * @throws BadPaddingException if data is not valid
     */
    public static String getDecryptedDataBase64(SecretKey key, byte[] data) throws BadPaddingException,IllegalBlockSizeException,
            InvalidKeyException {
        return Base64.getEncoder().encodeToString(decrypt(key,data));
    }

    /**
     * Decrypt data from BASE64 encrypted string and return decrypted data as BASE64 string
     *
     * @param key                Secret key to decrypt
     * @param base64EncodeString data as BASE64
     * @return decrypted data as BASE64 string
     * @throws InvalidKeyException if public key is invalid
     * @throws IllegalBlockSizeException if data is not valid
     * @throws BadPaddingException if data is not valid
     */
    public static String getDecryptedDataBase64(SecretKey key, String base64EncodeString) throws BadPaddingException,IllegalBlockSizeException,
            InvalidKeyException {
        return Base64.getEncoder().encodeToString(decrypt(key,Base64.getDecoder().decode(base64EncodeString)));
    }


    /**
     *
     * @return Algorithm name as String
     */
    public static String getAlgorithm() {
        return ALGORITHM;
    }
}
