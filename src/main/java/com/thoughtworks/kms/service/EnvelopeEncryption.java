package com.thoughtworks.kms.service;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.DataKeySpec;
import com.amazonaws.services.kms.model.GenerateDataKeyRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyResult;
import com.thoughtworks.kms.model.EnvelopeEncryptedMessage;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static com.thoughtworks.kms.service.EnvelopeEncryptionService.*;

public class EnvelopeEncryption
{
    private final AWSKMS awskms;

    private final String kmsKeyId;

    private volatile byte[] dataKey;

    private volatile byte[] encryptedDataKey;

    public EnvelopeEncryption(AWSKMS awskms, String kmsKeyId)
    {
        this.kmsKeyId = kmsKeyId;
        this.awskms = awskms;
    }

    public EnvelopeEncryptedMessage encrypt(String plainText) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException
    {
        if (isDataKeyEmpty()) {
            synchronized (this) {
                GenerateDataKeyResult generateDataKeyResult = generateDataKey();
                dataKey = generateDataKeyResult.getPlaintext().array();
                encryptedDataKey = generateDataKeyResult.getCiphertextBlob().array();
                return encryptMessage(plainText);
            }
        }
        return encryptMessage(plainText);
    }

    private EnvelopeEncryptedMessage encryptMessage(String plainText) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException
    {
        Cipher cipher = Cipher.getInstance(AES);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(dataKey, AES));
        byte[] encryptedText = cipher.doFinal(plainText.getBytes());
        String cipherText = Base64.getEncoder().encodeToString(encryptedText);
        EnvelopeEncryptedMessage envelope = new EnvelopeEncryptedMessage();
        envelope.setEncryptedKey(encryptedDataKey);
        envelope.setEncryptedMessage(cipherText);
        return envelope;
    }

    private GenerateDataKeyResult generateDataKey()
    {
        GenerateDataKeyRequest generateDataKeyRequest = new GenerateDataKeyRequest();
        generateDataKeyRequest.setKeyId(kmsKeyId);
        generateDataKeyRequest.setKeySpec(DataKeySpec.AES_128);
        return awskms.generateDataKey(generateDataKeyRequest);

    }

    private boolean isDataKeyEmpty()
    {
        return dataKey == null || encryptedDataKey == null;
    }
}
