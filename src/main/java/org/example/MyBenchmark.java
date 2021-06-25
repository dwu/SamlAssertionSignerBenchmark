package org.example;

import org.example.samlutil.KeyUtil;
import org.example.samlutil.SamlBuilder;
import org.example.samlutil.SamlUtil;
import org.joda.time.DateTime;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.security.x509.BasicX509Credential;

import java.io.File;
import java.security.KeyStore;
import java.util.concurrent.TimeUnit;

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

    @Benchmark
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @Warmup(iterations = 5)
    @Measurement(iterations = 5)
    @BenchmarkMode(Mode.AverageTime)
    public void buildAndSignAssertion2048(MyState myState, Blackhole bh) {
        Assertion assertion = myState.samlBuilder.buildAssertion("my-id", new DateTime(), "idOne", "idTwo");
        SamlUtil.signAssertion(assertion, myState.privateKeyCredential2048);
        bh.consume(assertion);
    }

    @Benchmark
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @Warmup(iterations = 5)
    @Measurement(iterations = 5)
    @BenchmarkMode(Mode.AverageTime)
    public void buildAndSignAssertion4096(MyState myState, Blackhole bh) {
        Assertion assertion = myState.samlBuilder.buildAssertion("my-id", new DateTime(), "idOne", "idTwo");
        SamlUtil.signAssertion(assertion, myState.privateKeyCredential4096);
        bh.consume(assertion);
    }

    @Benchmark
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @Warmup(iterations = 5)
    @Measurement(iterations = 5)
    @BenchmarkMode(Mode.AverageTime)
    public void buildAndSignAssertion8192(MyState myState, Blackhole bh) {
        Assertion assertion = myState.samlBuilder.buildAssertion("my-id", new DateTime(), "idOne", "idTwo");
        SamlUtil.signAssertion(assertion, myState.privateKeyCredential8192);
        bh.consume(assertion);
    }
}
