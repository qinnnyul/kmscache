package com.thoughtworks.kms.service;

import com.amazonaws.services.kms.AWSKMS;
import com.thoughtworks.kms.model.EnvelopeEncryptedMessage;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class EnvelopeEncryptionService
{
    public final static String AES = "AES";

    private final EnvelopeEncryption envelopeEncryptor;
    private final EnvelopeDecryption envelopeDecryptor;

    public EnvelopeEncryptionService(final AWSKMS awskms, final String kmsKeyId)
    {

        this.envelopeEncryptor = new EnvelopeEncryption(awskms, kmsKeyId);
        this.envelopeDecryptor = new EnvelopeDecryption(awskms, kmsKeyId);
    }

    public EnvelopeEncryptedMessage encrypt(String plainText) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException,
            NoSuchAlgorithmException, NoSuchPaddingException
    {
        return envelopeEncryptor.encrypt(plainText);
    }


    public String decrypt(EnvelopeEncryptedMessage envelopeEncryptedMessage) throws NoSuchAlgorithmException, BadPaddingException,
            NoSuchPaddingException, IllegalBlockSizeException, InvalidKeyException
    {
        return envelopeDecryptor.decrypt(envelopeEncryptedMessage);
    }

}