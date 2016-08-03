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