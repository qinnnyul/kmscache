package com.thoughtworks.kms;

import com.amazonaws.services.kms.AWSKMS;
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

public class EnvelopeEncryptionService
{
    private static final String AES = "AES";

    private final AWSKMS awskms;

    private final String kmsKeyId;

    private volatile byte[] dataKey;

    private volatile byte[] encryptedDataKey;

    public EnvelopeEncryptionService(final AWSKMS awskms, final String kmsKeyId)
    {

        this.awskms = awskms;
        this.kmsKeyId = kmsKeyId;
    }

    public EnvelopeEncryptedMessage encrypt(String plainText) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException,
            NoSuchAlgorithmException, NoSuchPaddingException
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


    public String decrypt(EnvelopeEncryptedMessage envelopeEncryptedMessage) throws NoSuchAlgorithmException, BadPaddingException,
            NoSuchPaddingException, IllegalBlockSizeException, InvalidKeyException
    {
        if (isDataKeyChangedOrEmpty(envelopeEncryptedMessage)) {
            synchronized (this) {
                DecryptResult decryptResult = decryptDataKey(envelopeEncryptedMessage);
                dataKey = decryptResult.getPlaintext().array();
                encryptedDataKey = envelopeEncryptedMessage.getEncryptedKey();
                return decryptMessage(envelopeEncryptedMessage);
            }
        }
        return decryptMessage(envelopeEncryptedMessage);
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


    private String decryptMessage(EnvelopeEncryptedMessage envelopeEncryptedMessage) throws InvalidKeyException, NoSuchPaddingException,
            NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException
    {
        byte[] decode = Base64.getDecoder().decode(envelopeEncryptedMessage.getEncryptedMessage());
        Cipher cipher = Cipher.getInstance(AES);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(dataKey, AES));
        return new String(cipher.doFinal(decode));
    }

    private DecryptResult decryptDataKey(final EnvelopeEncryptedMessage envelope)
    {
        ByteBuffer encryptedKey = ByteBuffer.wrap(envelope.getEncryptedKey());
        DecryptRequest decryptRequest = new DecryptRequest().withCiphertextBlob(encryptedKey);
        return awskms.decrypt(decryptRequest);
    }

    private boolean isDataKeyEmpty()
    {
        return dataKey == null || encryptedDataKey == null;
    }

    private boolean isDataKeyChangedOrEmpty(EnvelopeEncryptedMessage envelopeEncryptedMessage)
    {
        return encryptedDataKey == null || !Arrays.equals(envelopeEncryptedMessage.getEncryptedKey(), encryptedDataKey);
    }

}