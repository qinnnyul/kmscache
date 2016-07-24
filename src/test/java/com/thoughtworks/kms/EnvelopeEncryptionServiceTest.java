package com.thoughtworks.kms;

import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.kms.AWSKMSClient;
import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;

public class EnvelopeEncryptionServiceTest
{
    private EnvelopeEncryptionService classUnderTest;

    @Before
    public void setUp() throws Exception
    {
        AWSKMSClient awskmsClient = new AWSKMSClient();
        awskmsClient.setRegion(Region.getRegion(Regions.AP_SOUTHEAST_2));

        String kmsKeyId = "arn:aws:kms:ap-southeast-2:669606450274:key/b8b8f314-f55d-41e8-a8fe-b19a82f2201a";

        classUnderTest = new EnvelopeEncryptionService(awskmsClient, kmsKeyId);

    }

    @Test
    public void shouldEncryptAndDecryptDataWithKms() throws Exception
    {
        // when
        EnvelopeEncryptedMessage envelopeEncryptedMessage = classUnderTest.encrypt("hello world");
        // then
        assertNotNull(envelopeEncryptedMessage.getEncryptedMessage());
        assertNotNull(envelopeEncryptedMessage.getEncryptedKey());

        String plainText = classUnderTest.decrypt(envelopeEncryptedMessage);

        assertThat(plainText, is("hello world"));
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
    public void shouldUsingCacheKeyToDecryptData() throws Exception
    {
        // given
        EnvelopeEncryptedMessage envelopeEncryptedMessage = classUnderTest.encrypt("say hello");

        String result1 = classUnderTest.decrypt(envelopeEncryptedMessage);
        String result2 = classUnderTest.decrypt(envelopeEncryptedMessage);
        // when
        assertThat(result1.equals(result2), is(true));

    }
}