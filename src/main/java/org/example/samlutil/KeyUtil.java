/*
    Based on https://github.com/wayne989/OpenSAML3Example
 */

package org.example.samlutil;

import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.security.x509.X509Credential;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;


public class KeyUtil {

    public static PrivateKey getPrivateKey(KeyStore keyStore, String keyAlias, String keyPassword) throws Exception {
        PrivateKey privateKey = null;

        Key key = keyStore.getKey(keyAlias, keyPassword.toCharArray());
        if (key instanceof PrivateKey) {
            privateKey = (PrivateKey) key;
        }

        return privateKey;
    }

    public static KeyStore getKeyStore(File keyStoreFile, String keyStorePassword) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        FileInputStream is = new FileInputStream(keyStoreFile);
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(is, keyStorePassword.toCharArray());

        return ks;
    }

    public static X509Credential getCredential(KeyStore keyStore, String keyAlias, String password) throws Exception {
        KeyStore.PrivateKeyEntry pkEntry = (PrivateKeyEntry) keyStore.getEntry(keyAlias, new KeyStore.PasswordProtection(password.toCharArray()));
        PrivateKey pk = pkEntry.getPrivateKey();
        X509Certificate certificate = (X509Certificate) pkEntry.getCertificate();
        BasicX509Credential basicCredential = new BasicX509Credential(certificate);
        basicCredential.setPrivateKey(pk);
        return basicCredential;
    }

}
