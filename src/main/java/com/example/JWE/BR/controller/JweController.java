package com.example.JWE.BR.controller;

import com.example.JWE.BR.data.Request;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.nio.file.Files;
import java.nio.file.Paths;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/jwe")
public class JweController {
   @Value("${microservice.parameters.KEY_SIZE}")
    private int KEY_SIZE;
    @Value("${microservice.parameters.PUBLIC_KEY_PATH_FILE}")
    private String PUBLIC_KEY_PATH_FILE;
    @Value("${microservice.parameters.ENCRYPT_SECRET}")
    private Boolean ENCRYPT_SECRET;
    private static final String PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC2txPHmrQi0XqbgYm4PJoV9c3uep6BUcraQHmeXPNqBr42ZPDiFrBcxd18Oj48x8Thnvo3rD89+X4swFzJCSnb/bJAiavaEt2ZxtI2CgqQW2HAuf0wZRlabMa00QACxIN1uhWmANJ3iY7E4tNSQHcbQXzmOCUULFeiPpoT3MdIBwG+OL04ZCaai+ZQgd301oZAQ9ysXbnx3bOI3LOr4zJPqOcnd9mC0mj+aBfszjB7saCh7zyEtAPghG3yn5gvA3PaD2eU4wtghzxTdMoq9tSBT2Hy4D2hzPGoi1e8mv5giBkpQahx/WDXfF1sMnkpW1EO0qUft2lhJsENXXq1Ac0fAgMBAAECggEAFVYZrDRnlq1JmQEueOIyyB+1FYUiH03S11uyGAkYr6fr7GQrMOufWqYMcCZJAEX/uq0a4QdvNyh8UHOCIkO8rKDagOjStZuAXyW1hHP1udfB+YR+iXk01bdgGNtTGf+irku1nXX5HdZlYp5uOOuoPPmPwT6LLejjruGKkok0iDd+q/K7aWDbitPs2+Swv+vwh4XZkkh30Nq4DUjmuFMb2U+zcKZk8ZYML3Yl95NcLgAL5dWQHr5wx26k6uw8Udnykp38FfybTnsreuhl28mW0frvwlRjvZ3fdBWwCz2bSOZGsjz+fMCZGQjRW9U+FTdBIeVmABttQ7sPzl4eTnEhoQKBgQDjkeXygMIa+wLru688WnlKuhht4jqTn+SvRiGIqgCTFJttivQtM1LkfVQEc6aeluXyA+o5HCDczOjEughEPurHGVPiydBWwNlxpmUDxV8Zh+mCFCj1H4lyduvwX7+GoqoFehDzOUsiyBV2Tch/dpJuAEZioZ4w64z2yEJ7yqjO8QKBgQDNiqQ7nEto/smmZDM/31EkQp6Z50WRQIbim+EieEYZabLDsYbucZW8lZsriKGj+of7FxAnbMVYUhSKfn+aYfRVOfCmE/CCRvN4ptgFJQR1gtKQt1bXgumC8RdSMNBpTrD3EQtrVjsHPxKGwiLcjBqprvX32Lx7bEHL0+j2zTJ9DwKBgCYxW01KzMjobcIQesV/TbH775OpjzktcZz1ATXFilkk8Tz+QCLB5VyRqCMjIcil/KuUep/hF6bXAQ3bRv3lLVQC7TA3vK6CqTvIuFVcr6xCQi9hoMoa49+BE/IAr80xyaUnqmaXrAOHXwq+3TJ/PO4XP7jX9QuyzLKyQ24xQgmRAoGABKHcQ6+pD2u2lbZqZUUeKggKVQOeUMC4iYDj2QgG5Gm6aqikltkee8qPXbLNmcl6qREC/zB3Xh8zcU+ahpswi38rykJmyDjbIdv4wFzuNcvF/Rb0sRS1OItAcEzDVaw9VsQeksO1vtsQCtNzP680pqBX0McksE9nSDW1aWKEgccCgYEAl4BqWGYpycOXOSNpZbkoMHV9hG9FWfZ3hHn/DDutMAkrFWgIhdBQnfqRYtctSb3lG3ch2VL26sb3xVbOXChvUbsvdxn6M780jvJpFg/sjBvvef9f2AWNLOxktbuWyHM3mVgLTlniw5H/y6rqgC+3Z4UexsBKjU8XYJiajkpTQ5Y=-----END PRIVATE KEY-----";


    /* private static final String PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----MIICeQIBADANBgkqhkiG9w0BAQEFAASCAmMwggJfAgEAAoGBALQe9NBzMkFq69A96pr7no8u5e9+n2APdj8O3s+k22yPgfYUYmvD+ImujSoPlXw/rM++PMe1DNuoCQhOgAwyUdQoYwPMi2jRTbHBB8ycZe0nFoRWBrtUpNI1f9vRXvLdiBF8LWAkgtNIK1BGaY1pw6q5CxxO+AAEq7mqt+L+sgKlAgMBAAECgYEAgV0eXTvvIzbEqKpfffIrnhCDyi96DcbtGTr34dA4W87x+ygGy/lS3qfD8SqCJVuiJQ4vnws0cepMmm+u3ZOiWnL4DeMIRzb0fHFK6MvqVkbbtOCbS9UQXBJlTjugtM8WM1xt4CK2MKXi4fo9I+XWvEWltv0xC+96USuJ/uwg/50CQQD4PaYokMGan8P78IpPDzTAqdOgmFBAmdc1yozDTt4g63bUqJ6PKEWTbxumWIj7MN7ayNC5pgPTQvTLrB12IvU/AkEAucA7TKF152kBf2mD6V3z8XqkbRgRsdgIxXNw9Jqgke7oS6v/6iHhCKdBhoZuDdL9fW0clNuWMMFWNVOa5zubGwJBANYpeZwtppmblB1bHDewyrYczbMTNMlG7+A8asxk0kZcXhyBjKm8+KmFhbkxUJxFQT5HWauQimRMs5yzVIeDCUkCQQCS+N4yuQKAcp5jwQpFyTgulnqpc0T08dmm2bvDXuGz9lPJJDPefqX+4dA/7/f+ajZ2WrIlukVxGFjs4tULJyeHAkEAztPHHWH8/a8J/Km0M3bD3LFFWg5cn4aXHCEmMRxxSyveTvg/e2mZgCyoBIxRiU685lF2N97rnSrWoVLqN9omQQ==-----END RSA PRIVATE KEY-----";*/


    @PostMapping("/encrypt")
    public String encrypt(@RequestBody Request json) throws Exception {

        String jsonReq = json.getJsonReq();
        String pathFile = json.getFilePath();

        byte[] secretKey = generateSecretKey(KEY_SIZE);
        System.out.println("secretKey : " + secretKey);
        String secreteClaro = Base64.getEncoder().encodeToString(secretKey);
        System.out.println("SECRETO TEXTO CLARO:  " + secreteClaro);

        if (ENCRYPT_SECRET) {
            PublicKey serverPublicKey = getPublicKey(PUBLIC_KEY_PATH_FILE + pathFile);
            String encryptedSecretKey = encryptSecretKey(secretKey, serverPublicKey);
            System.out.println("SECRETO ENCRIPTADO:  " + encryptedSecretKey);
            String encryptedJson = encryptJson(jsonReq, secretKey);
            System.out.println("Encrypted JSON: " + encryptedJson);
            return "{"
                    + "\"encryptedJson\":\"" + encryptedJson + "\","
                    + "\"encryptedSecretKey\":\"" + encryptedSecretKey + "\""
                    + "}";
        } else {
            String encryptedJson = encryptJson(jsonReq, secretKey);
            System.out.println("Encrypted JSON: " + encryptedJson);
            return "{"
                    + "\"encryptedJson\":\"" + encryptedJson + "\","
                    + "\"encryptedSecretKey\":\"" + secreteClaro + "\""
                    + "}";
        }
    }

    @PostMapping("/decrypt")
    public String decrypt(@RequestHeader("x-key") String encryptedSecretKey, @RequestBody String encryptedJson)
            throws Exception {

        PrivateKey serverPrivateKey = getPrivateKeyFromString(PRIVATE_KEY);

        if (ENCRYPT_SECRET) {
            String decryptedSecretKey = decryptSecretKey(encryptedSecretKey, serverPrivateKey);
            System.out.println("SECRETO DESENCRIPTADO:  " + decryptedSecretKey);
            byte[] decryptedSecretKeyByte = Base64.getDecoder().decode(decryptedSecretKey);
            String decryptedMessage = decryptWithJwe(encryptedJson, decryptedSecretKeyByte);
            System.out.println("Decrypted Message: " + decryptedMessage);
            return decryptedMessage;
        } else {
            byte[] decryptedSecretKey = Base64.getDecoder().decode(encryptedSecretKey);
            System.out.println("SECRET BASE 64: " + decryptedSecretKey);
            String decryptedMessage = decryptWithJwe(encryptedJson, decryptedSecretKey);
            System.out.println("Decrypted Message: " + decryptedMessage);
            return decryptedMessage;      
        }

    }

    private static byte[] generateSecretKey(int keySize) throws Exception {
        SecureRandom secureRandom = SecureRandom.getInstanceStrong();
        byte[] randomBytes = new byte[keySize];
        secureRandom.nextBytes(randomBytes);
        return randomBytes;
    }

    private static String encryptJson(String json, byte[] secretKey) throws Exception {
        SecretKey key = new SecretKeySpec(secretKey, "AES");
        JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM);
        Payload payload = new Payload(json);
        JWEObject jweObject = new JWEObject(header, payload);
        jweObject.encrypt(new DirectEncrypter(key));
        return jweObject.serialize();
    }

    private static String encryptSecretKey(byte[] secretKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(secretKey));
    }

    private static String decryptSecretKey(String encryptedSecretKey, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedSecretKey)));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static String decryptWithJwe(String JsonEncrypt, byte[] secretKey) throws ParseException, JOSEException {
        SecretKey key = new SecretKeySpec(secretKey, "AES"); 
        JWEObject jweObject = JWEObject.parse(JsonEncrypt);
        jweObject.decrypt(new DirectDecrypter(key));
        return jweObject.getPayload().toString();
    }

    private static PublicKey getPublicKey(String path) {
        try {

            String publicKeyPEM = new String(Files.readAllBytes(Paths.get(path)))
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s+", "")
                    .replaceAll(System.lineSeparator(), "");
            System.out.println("PUBLIC KEY: " + publicKeyPEM);
            byte[] keyBytes = Base64.getDecoder().decode(publicKeyPEM);

            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(keySpec);
            return publicKey;
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e);
            return null;
        }
    }

    private static PrivateKey getPrivateKeyFromString(String key) throws Exception {
        String privateKeyPEM = key.replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return keyFactory.generatePrivate(keySpec);
    }
}
