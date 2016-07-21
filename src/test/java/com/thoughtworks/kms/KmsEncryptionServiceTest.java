package com.thoughtworks.kms;

import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.kms.AWSKMSClient;
import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;

public class KmsEncryptionServiceTest
{
    private KmsEncryptionService classUnderTest;

    String mockedEncryptedKey = "\u0007\u00010\u001E\u0006\t`�H\u0001e\u0003\u0004\u0001" +
            ".0\u0011\u0004\f4v\u0016\u0000\u0017£>�e�x\u0002\u0001\u0010�+\u0010\u0004\u001EO��S�\u0007`#�2��%��,+�%��\u001C��0�Q\u001B";
    String cipherText = "yka5nqvgFmANJLNqAVTuZQ";


    @Before
    public void setUp() throws Exception
    {
        AWSKMSClient awskmsClient = new AWSKMSClient();
        awskmsClient.setRegion(Region.getRegion(Regions.AP_SOUTHEAST_2));

        String kmsKeyId = "arn:aws:kms:ap-southeast-2:669606450274:key/b8b8f314-f55d-41e8-a8fe-b19a82f2201a";

        classUnderTest = new KmsEncryptionService(awskmsClient, kmsKeyId);

    }

    @Test
    public void shouldEncryptDataWithKms() throws Exception
    {
        // when
        EnvelopeEncryptedMessage envelopeEncryptedMessage = classUnderTest.encrypt("hello world");
        // then
        assertNotNull(envelopeEncryptedMessage.getCiphertext());
        assertNotNull(envelopeEncryptedMessage.getEncryptedKey());
    }

    @Test
    public void shouldUsingCachedKeyToEncryptData() throws Exception
    {
        // when
        EnvelopeEncryptedMessage envelopeEncryptedMessage1 = classUnderTest.encrypt("hello world");
        EnvelopeEncryptedMessage envelopeEncryptedMessage2 = classUnderTest.encrypt("sldjfsdald");

        // then
        assertThat(new String(envelopeEncryptedMessage1.getEncryptedKey()).equals(new String(envelopeEncryptedMessage2.getEncryptedKey())), is(true));
    }

    @Test
    public void shouldDecryptDataWithKmsCache() throws Exception
    {

        EnvelopeEncryptedMessage envelopeEncryptedMessage = new EnvelopeEncryptedMessage();
        envelopeEncryptedMessage.setCiphertext(cipherText);
        envelopeEncryptedMessage.setEncryptedKey(mockedEncryptedKey.getBytes());

        // when
        String plainText = classUnderTest.decrypt(envelopeEncryptedMessage);

        // then
        assertThat(plainText, is("hello world"));
    }
}