package com.thoughtworks.kms.config;

import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClient;
import com.thoughtworks.kms.service.EnvelopeEncryptionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConditionalOnMissingBean(EnvelopeEncryptionService.class)
@EnableConfigurationProperties(KMSConfigurationProperties.class)
public class KMSEncryptionConfiguration
{
    @Autowired
    private KMSConfigurationProperties kmsConfigurationProperties;

    @Autowired
    private AWSKMS awskms;

    @Bean
    public EnvelopeEncryptionService envelopeEncryptionService()
    {
        return new EnvelopeEncryptionService(awskms, kmsConfigurationProperties.getKeyId());
    }


    @Configuration
    @ConditionalOnMissingBean(AWSKMS.class)
    @EnableConfigurationProperties(KMSConfigurationProperties.class)
    static class KMSConfiguration
    {

        @Autowired
        private KMSConfigurationProperties kmsConfigurationProperties;

        @Bean
        AWSKMS awskms()
        {
            final AWSKMSClient awskmsClient = new AWSKMSClient();
            awskmsClient.setRegion(Region.getRegion(Regions.fromName(kmsConfigurationProperties.getRegion())));
            return awskmsClient;
        }

    }

}
