package org.example;

import java.io.File;
import java.security.KeyStore;
import java.util.concurrent.TimeUnit;

import org.example.samlutil.KeyUtil;
import org.example.samlutil.SamlBuilder;
import org.example.samlutil.SamlUtil;
import org.joda.time.DateTime;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.support.SignatureConstants;

@Fork(1)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 5)
@Measurement(iterations = 5)
@BenchmarkMode(Mode.AverageTime)
public class MyBenchmark {

	@State(Scope.Thread)
    public static class MyState {

        public KeyStore keyStore;
        public BasicX509Credential privateKeyCredential2048;
        public BasicX509Credential privateKeyCredential4096;
        public BasicX509Credential privateKeyCredential8192;
        public SamlBuilder samlBuilder;

        @Setup(Level.Trial)
        public void doSetup() {
            try {
                samlBuilder = new SamlBuilder();
                keyStore = KeyUtil.getKeyStore(new File("keystore.jks"), "password");
                privateKeyCredential2048 = (BasicX509Credential) KeyUtil.getCredential(keyStore, "test2048", "password");
                privateKeyCredential4096 = (BasicX509Credential) KeyUtil.getCredential(keyStore, "test4096", "password");
                privateKeyCredential8192 = (BasicX509Credential) KeyUtil.getCredential(keyStore, "test8192", "password");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

    }
    
    // Key Length 2048 bit

    @Benchmark
    public void buildAndSignAssertion2048RsaSha1(MyState myState, Blackhole bh) {
        Assertion assertion = myState.samlBuilder.buildAssertion("my-id", new DateTime(), "idOne", "idTwo");
        SamlUtil.signAssertion(assertion, myState.privateKeyCredential2048, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
        bh.consume(assertion);
    }

    @Benchmark
    public void buildAndSignAssertion2048RsaSha256(MyState myState, Blackhole bh) {
        Assertion assertion = myState.samlBuilder.buildAssertion("my-id", new DateTime(), "idOne", "idTwo");
        SamlUtil.signAssertion(assertion, myState.privateKeyCredential2048, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        bh.consume(assertion);
    }
    
    @Benchmark
    public void buildAndSignAssertion2048RsaSha384(MyState myState, Blackhole bh) {
        Assertion assertion = myState.samlBuilder.buildAssertion("my-id", new DateTime(), "idOne", "idTwo");
        SamlUtil.signAssertion(assertion, myState.privateKeyCredential2048, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA384);
        bh.consume(assertion);
    }
    
    @Benchmark
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @Fork(value = 3, warmups = 2)
    @BenchmarkMode(Mode.AverageTime)
    public void buildAndSignAssertion2048RsaSha512(MyState myState, Blackhole bh) {
        Assertion assertion = myState.samlBuilder.buildAssertion("my-id", new DateTime(), "idOne", "idTwo");
        SamlUtil.signAssertion(assertion, myState.privateKeyCredential2048, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512);
        bh.consume(assertion);
    }
    
    // Key Length 4096 bit    
    
    @Benchmark
    public void buildAndSignAssertion4096RsaSha1(MyState myState, Blackhole bh) {
        Assertion assertion = myState.samlBuilder.buildAssertion("my-id", new DateTime(), "idOne", "idTwo");
        SamlUtil.signAssertion(assertion, myState.privateKeyCredential4096, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
        bh.consume(assertion);
    }

    @Benchmark
    public void buildAndSignAssertion4096RsaSha256(MyState myState, Blackhole bh) {
        Assertion assertion = myState.samlBuilder.buildAssertion("my-id", new DateTime(), "idOne", "idTwo");
        SamlUtil.signAssertion(assertion, myState.privateKeyCredential4096, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        bh.consume(assertion);
    }

    @Benchmark
    public void buildAndSignAssertion4096RsaSha384(MyState myState, Blackhole bh) {
        Assertion assertion = myState.samlBuilder.buildAssertion("my-id", new DateTime(), "idOne", "idTwo");
        SamlUtil.signAssertion(assertion, myState.privateKeyCredential4096, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA384);
        bh.consume(assertion);
    }

    @Benchmark
    public void buildAndSignAssertion4096RsaSha512(MyState myState, Blackhole bh) {
        Assertion assertion = myState.samlBuilder.buildAssertion("my-id", new DateTime(), "idOne", "idTwo");
        SamlUtil.signAssertion(assertion, myState.privateKeyCredential4096, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512);
        bh.consume(assertion);
    }

    // Key Length 8192 bit
    
    @Benchmark
    public void buildAndSignAssertion8192RsaSha1(MyState myState, Blackhole bh) {
        Assertion assertion = myState.samlBuilder.buildAssertion("my-id", new DateTime(), "idOne", "idTwo");
        SamlUtil.signAssertion(assertion, myState.privateKeyCredential8192, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
        bh.consume(assertion);
    }

    @Benchmark
    public void buildAndSignAssertion8192RsaSha256(MyState myState, Blackhole bh) {
        Assertion assertion = myState.samlBuilder.buildAssertion("my-id", new DateTime(), "idOne", "idTwo");
        SamlUtil.signAssertion(assertion, myState.privateKeyCredential8192, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        bh.consume(assertion);
    }
    
    @Benchmark
    public void buildAndSignAssertion8192RsaSha384(MyState myState, Blackhole bh) {
        Assertion assertion = myState.samlBuilder.buildAssertion("my-id", new DateTime(), "idOne", "idTwo");
        SamlUtil.signAssertion(assertion, myState.privateKeyCredential8192, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA384);
        bh.consume(assertion);
    }
    
    @Benchmark
    public void buildAndSignAssertion8192RsaSha512(MyState myState, Blackhole bh) {
        Assertion assertion = myState.samlBuilder.buildAssertion("my-id", new DateTime(), "idOne", "idTwo");
        SamlUtil.signAssertion(assertion, myState.privateKeyCredential8192, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512);
        bh.consume(assertion);
    }

}
