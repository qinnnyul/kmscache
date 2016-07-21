package com.thoughtworks.kms;

import com.amazonaws.services.kms.AWSKMSClient;
import com.amazonaws.services.kms.model.DataKeySpec;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;
import com.amazonaws.services.kms.model.GenerateDataKeyRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyResult;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

public class KmsEncryptionService
{
    private AWSKMSClient awskmsClient;

    private String kmsKeyId;

    private byte[] secretKey;

    private byte[] encryptedSecretKey;

    private static final String AES = "AES";

    public KmsEncryptionService(AWSKMSClient awskmsClient, String kmsKeyId)
    {

        this.awskmsClient = awskmsClient;
        this.kmsKeyId = kmsKeyId;
    }

    public EnvelopeEncryptedMessage encrypt(String plainText) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException,
            NoSuchAlgorithmException, NoSuchPaddingException
    {
        if (secretKey == null || encryptedSecretKey == null){
            GenerateDataKeyResult generateDataKeyResult = generateDataKey();
            secretKey = generateDataKeyResult.getPlaintext().array();
            encryptedSecretKey = generateDataKeyResult.getCiphertextBlob().array();
        }
        return encryptMessage(plainText);
    }


    private EnvelopeEncryptedMessage encryptMessage(String plainText) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException
    {
        Cipher cipher = Cipher.getInstance(AES);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(secretKey, AES));
        byte[] enc = cipher.doFinal(plainText.getBytes());
        String cipherText = Base64.getEncoder().encodeToString(enc);
        EnvelopeEncryptedMessage envelope = new EnvelopeEncryptedMessage();
        envelope.setEncryptedKey(encryptedSecretKey);
        envelope.setCiphertext(cipherText);
        return envelope;
    }


    private GenerateDataKeyResult generateDataKey()
    {
        GenerateDataKeyRequest generateDataKeyRequest = new GenerateDataKeyRequest();
        generateDataKeyRequest.setKeyId(kmsKeyId);
        generateDataKeyRequest.setKeySpec(DataKeySpec.AES_128);
        return awskmsClient.generateDataKey(generateDataKeyRequest);

    }

    public String decrypt(EnvelopeEncryptedMessage envelopeEncryptedMessage) throws NoSuchAlgorithmException, BadPaddingException,
            NoSuchPaddingException, IllegalBlockSizeException, InvalidKeyException
    {
        if (encryptedSecretKey == null || !Arrays.equals(envelopeEncryptedMessage.getEncryptedKey(), encryptedSecretKey)){
            DecryptResult decryptResult = decryptKey(envelopeEncryptedMessage);
            secretKey = decryptResult.getPlaintext().array();
            encryptedSecretKey = envelopeEncryptedMessage.getEncryptedKey();
        }
        return decryptMessage(envelopeEncryptedMessage);
    }

    private String decryptMessage(EnvelopeEncryptedMessage envelopeEncryptedMessage) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException
    {
        byte[] decode = Base64.getDecoder().decode(envelopeEncryptedMessage.getCiphertext());
        Cipher cipher = Cipher.getInstance(AES);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(secretKey, AES));
        byte[] bytes = cipher.doFinal(decode);
        return Arrays.toString(bytes);
    }

    private DecryptResult decryptKey(final EnvelopeEncryptedMessage envelope) {
        ByteBuffer encryptedKey = ByteBuffer.wrap(envelope.getEncryptedKey());
        DecryptRequest decryptRequest = new DecryptRequest().withCiphertextBlob(encryptedKey);
        return awskmsClient.decrypt(decryptRequest);
    }
}