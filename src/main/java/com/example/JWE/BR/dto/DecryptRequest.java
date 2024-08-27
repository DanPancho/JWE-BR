package com.example.JWE.BR.dto;

public class DecryptRequest {
    private String encryptedJson;
    private String encryptedSecretKey;

    public String getEncryptedJson() {
        return encryptedJson;
    }

    public void setEncryptedJson(String encryptedJson) {
        this.encryptedJson = encryptedJson;
    }

    public String getEncryptedSecretKey() {
        return encryptedSecretKey;
    }

    public void setEncryptedSecretKey(String encryptedSecretKey) {
        this.encryptedSecretKey = encryptedSecretKey;
    }
}
