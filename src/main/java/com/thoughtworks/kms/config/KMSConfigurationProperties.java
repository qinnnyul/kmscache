package com.thoughtworks.kms.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "aws.kms")
public class KMSConfigurationProperties
{
    private String enable;
    private String keyId;
    private String region;

    public String getEnable()
    {
        return enable;
    }

    public void setEnable(String enable)
    {
        this.enable = enable;
    }

    public String getKeyId()
    {
        return keyId;
    }

    public void setKeyId(String keyId)
    {
        this.keyId = keyId;
    }

    public String getRegion()
    {
        return region;
    }

    public void setRegion(String region)
    {
        this.region = region;
    }
}
