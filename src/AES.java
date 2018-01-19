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

    public static byte[] encrypt(SecretKey key,byte[] data) throws InvalidKeyException,IllegalBlockSizeException,
            BadPaddingException
    {
        byte[] encriptedData=null;
        try
        {
            Cipher cipher=Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE,key);
            encriptedData= cipher.doFinal(data);

        } catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        } catch (NoSuchPaddingException e)
        {
            e.printStackTrace();
        }
        return encriptedData;
    }

    public static String getEncryptedDataBase64(SecretKey key,byte[] data) throws BadPaddingException,IllegalBlockSizeException,
            InvalidKeyException
    {
        return Base64.getEncoder().encodeToString(encrypt(key,data));
    }

    public static String getEncryptedDataBase64(SecretKey key,String base64EncodedString) throws BadPaddingException,IllegalBlockSizeException,
            InvalidKeyException
    {
        return Base64.getEncoder().encodeToString(encrypt(key,Base64.getDecoder().decode(base64EncodedString)));
    }

    public static byte[] decrypt(SecretKey key,byte[] encryptedData) throws BadPaddingException,IllegalBlockSizeException,
            InvalidKeyException
    {
        byte[] decryptedData=null;

        try
        {
            Cipher cipher =Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE,key);
            decryptedData = cipher.doFinal(encryptedData);

        } catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        } catch (NoSuchPaddingException e)
        {
            e.printStackTrace();
        }

        return decryptedData;
    }

    public static String getDecryptedDataBase64(SecretKey key,byte[] data) throws BadPaddingException,IllegalBlockSizeException,
            InvalidKeyException
    {
        return Base64.getEncoder().encodeToString(decrypt(key,data));
    }

    public static String getDecryptedDataBase64(SecretKey key,String base64EncodeString) throws BadPaddingException,IllegalBlockSizeException,
            InvalidKeyException
    {
        return Base64.getEncoder().encodeToString(decrypt(key,Base64.getDecoder().decode(base64EncodeString)));
    }


    public static String getAlgorithm()
    {
        return ALGORITHM;
    }
}
