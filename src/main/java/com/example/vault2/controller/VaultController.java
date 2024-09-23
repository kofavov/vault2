package com.example.vault2.controller;

import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.VaultResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.net.ssl.SSLContext;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;

@RestController
public class VaultController {

    private final VaultTemplate vaultTemplate;

    public VaultController(VaultTemplate vaultTemplate) {
        this.vaultTemplate = vaultTemplate;
    }

    @GetMapping("/vault")
    public String getCredentialsWithVaultTemplate() throws Exception {
        // Чтение секрета из пути 'secret/data/my-app'
        VaultResponse response = vaultTemplate.read("");

        if (response != null && response.getData() != null) {
            // Получаем значения username и password из Vault
            LinkedHashMap<String, String> data = (LinkedHashMap) response.getData().get("data");
            String cert = data.get("cert");
            String key = data.get("key");
            // Преобразуем сертификат в X509Certificate
            X509Certificate certificate = getCertificateFromString(cert);

            // Преобразуем закрытый ключ в PrivateKey
            PrivateKey privateKey = getPrivateKeyFromString(key);

            // Создание SSLContext
            SSLContext sslContext = createSSLContext(certificate, privateKey);

            return "SSLContext successfully created: " + sslContext.getProtocol();
        } else {
            return "No data found at the specified path";
        }
    }

    // Метод для преобразования строки сертификата в X509Certificate
    private X509Certificate getCertificateFromString(String certString) throws Exception {
        String certCleaned = certString
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");

        byte[] certBytes = Base64.getDecoder().decode(certCleaned);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(new java.io.ByteArrayInputStream(certBytes));
    }

    // Метод для преобразования строки ключа в PrivateKey
    private PrivateKey getPrivateKeyFromString(String keyString) throws Exception {
        String keyCleaned = keyString
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(keyCleaned);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    // Метод для создания SSLContext
    private SSLContext createSSLContext(X509Certificate certificate, PrivateKey privateKey) throws Exception {
        // Создание ключевого хранилища с сертификатом и ключом
        java.security.KeyStore keyStore = java.security.KeyStore.getInstance("JKS");
        keyStore.load(null, null);
        keyStore.setKeyEntry("mykey", privateKey, "password".toCharArray(), new java.security.cert.Certificate[]{certificate});

        // Инициализация KeyManagerFactory
        javax.net.ssl.KeyManagerFactory kmf = javax.net.ssl.KeyManagerFactory.getInstance(javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, "password".toCharArray());

        // Инициализация SSLContext
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), null, null);

        return sslContext;
    }
}
