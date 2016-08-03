package com.thoughtworks.kms.model;

public final class EnvelopeEncryptedMessage
{

    private byte[] encryptedKey;
    private String encryptedMessage;

    public byte[] getEncryptedKey() {
        return encryptedKey;
    }

    public void setEncryptedKey(byte[] encryptedKey) {
        this.encryptedKey = encryptedKey;
    }

    public void setEncryptedMessage(String encryptedMessage) {
        this.encryptedMessage = encryptedMessage;
    }

    public String getEncryptedMessage() {
        return encryptedMessage;
    }


}
