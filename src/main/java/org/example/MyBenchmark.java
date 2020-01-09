/*
 * Copyright (c) 2014, Oracle America, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 *  * Neither the name of Oracle nor the names of its contributors may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

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

@State(Scope.Thread)
public class MyBenchmark {

    @State(Scope.Thread)
    public static class MyState {

        public KeyStore keyStore;
        public BasicX509Credential privateKeyCredential;
        public SamlBuilder samlBuilder;

        @Setup(Level.Trial)
        public void doSetup() {
            try {
                samlBuilder = new SamlBuilder();
                keyStore = KeyUtil.getKeyStore(new File("keystore.jks"), "password");
                privateKeyCredential = (BasicX509Credential) KeyUtil.getCredential(keyStore, "selfsigned", "password");
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
    public void buildAndSignAssertion(MyState myState, Blackhole bh) {
        Assertion assertion = myState.samlBuilder.buildAssertion("my-id", new DateTime(), "idOne", "idTwo");
        SamlUtil.signAssertion(assertion, myState.privateKeyCredential);
        bh.consume(assertion);
    }

}
