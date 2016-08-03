package com.thoughtworks.kms;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import static com.thoughtworks.kms.EnvelopeEncryptionService.AES;

public class EnvelopeDecryption
{
    private final AWSKMS awskms;

    private final String kmsKeyId;

    private final ConcurrentMap<String, byte[]> cacheKeys = new ConcurrentHashMap<String, byte[]>();

    public EnvelopeDecryption(AWSKMS awskms, String kmsKeyId)
    {
        this.awskms = awskms;
        this.kmsKeyId = kmsKeyId;
    }

    public String decrypt(EnvelopeEncryptedMessage envelopeEncryptedMessage) throws NoSuchAlgorithmException, BadPaddingException,
            NoSuchPaddingException, IllegalBlockSizeException, InvalidKeyException
    {
        if (isDataKeyNotCached(envelopeEncryptedMessage)) {
            synchronized (this) {
                DecryptResult decryptResult = decryptDataKey(envelopeEncryptedMessage);
                cacheKeys.putIfAbsent(new String(envelopeEncryptedMessage.getEncryptedKey()), decryptResult.getPlaintext().array());
                return decryptMessage(envelopeEncryptedMessage);
            }
        }
        return decryptMessage(envelopeEncryptedMessage);
    }

    private String decryptMessage(EnvelopeEncryptedMessage envelopeEncryptedMessage) throws InvalidKeyException, NoSuchPaddingException,
            NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException
    {
        byte[] decode = Base64.getDecoder().decode(envelopeEncryptedMessage.getEncryptedMessage());
        Cipher cipher = Cipher.getInstance(AES);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cacheKeys.get(new String(envelopeEncryptedMessage.getEncryptedKey())), AES));
        return new String(cipher.doFinal(decode));
    }

    private DecryptResult decryptDataKey(final EnvelopeEncryptedMessage envelope)
    {
        ByteBuffer encryptedKey = ByteBuffer.wrap(envelope.getEncryptedKey());
        DecryptRequest decryptRequest = new DecryptRequest().withCiphertextBlob(encryptedKey);
        return awskms.decrypt(decryptRequest);
    }

    private boolean isDataKeyNotCached(EnvelopeEncryptedMessage envelopeEncryptedMessage)
    {
        return !cacheKeys.containsKey(new String(envelopeEncryptedMessage.getEncryptedKey()));
    }


}
