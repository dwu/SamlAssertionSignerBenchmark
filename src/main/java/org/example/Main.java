package org.example;

import org.example.samlutil.KeyUtil;
import org.example.samlutil.SamlBuilder;
import org.example.samlutil.SamlUtil;
import org.joda.time.DateTime;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.security.x509.BasicX509Credential;

import java.io.File;
import java.security.KeyStore;

public class Main {

    public void run() throws Exception {
        KeyStore keyStore = KeyUtil.getKeyStore(new File("keystore.jks"), "password");
        BasicX509Credential privateKeyCredential = (BasicX509Credential) KeyUtil.getCredential(keyStore, "test8192", "password");

        SamlBuilder samlBuilder = new SamlBuilder();
        Assertion assertion = samlBuilder.buildAssertion("my-id", new DateTime(), "idOne", "idTwo");
        SamlUtil.signAssertion(assertion, privateKeyCredential);
        String strResponse = SamlUtil.stringifySAMLObject(assertion);
        System.out.println(strResponse);
    }

    public static void main(String[] args) {
        try {
            Main m = new Main();
            m.run();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
