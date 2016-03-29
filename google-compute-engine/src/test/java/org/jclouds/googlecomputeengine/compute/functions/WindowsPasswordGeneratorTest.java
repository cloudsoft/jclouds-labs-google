/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jclouds.googlecomputeengine.compute.functions;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.isA;
import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.testng.Assert.assertEquals;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.concurrent.atomic.AtomicReference;

import javax.crypto.Cipher;

import org.jclouds.crypto.Crypto;
import org.jclouds.encryption.bouncycastle.BouncyCastleCrypto;
import org.jclouds.googlecomputeengine.GoogleComputeEngineApi;
import org.jclouds.googlecomputeengine.domain.Instance;
import org.jclouds.googlecomputeengine.domain.Instance.SerialPortOutput;
import org.jclouds.googlecomputeengine.domain.Metadata;
import org.jclouds.googlecomputeengine.domain.Operation;
import org.jclouds.googlecomputeengine.features.InstanceApi;
import org.jclouds.googlecomputeengine.parse.ParseInstanceTest;
import org.testng.annotations.Test;

import com.google.common.base.Predicate;
import com.google.common.base.Predicates;

@Test
public class WindowsPasswordGeneratorTest {
   public void testGeneratePassword() throws Exception {
      Crypto bcCrypto = new BouncyCastleCrypto();
      KeyPair keyPair = bcCrypto.rsaKeyPairGenerator().genKeyPair();
      Cipher cipher = bcCrypto.cipher("RSA/NONE/OAEPPadding");
      Predicate<AtomicReference<Operation>> operationDone = Predicates.alwaysTrue();
      Instance instance = new ParseInstanceTest().expected();
      String zone = "us-central1-a";
      
      GoogleComputeEngineApi api = createMock(GoogleComputeEngineApi.class);
      InstanceApi instanceApi = createMock(InstanceApi.class);
      Operation operation = createMock(Operation.class);
      SerialPortOutput serialPortOutput = createMock(SerialPortOutput.class);
      Crypto crypto = createMock(Crypto.class);
      KeyPairGenerator keyPairGenerator = createMock(KeyPairGenerator.class);
      
      expect(api.instancesInZone(zone)).andReturn(instanceApi).atLeastOnce();
      expect(crypto.rsaKeyPairGenerator()).andReturn(keyPairGenerator);
      expect(keyPairGenerator.genKeyPair()).andReturn(keyPair);
      // FIXME assert that metadata contained what we expected
      expect(instanceApi.setMetadata(eq(instance.id()), isA(Metadata.class))).andReturn(operation).atLeastOnce();
      expect(operation.httpErrorStatusCode()).andReturn(null);
      expect(instanceApi.getSerialPortOutput(instance.id(), 4)).andReturn(serialPortOutput).atLeastOnce();
      expect(serialPortOutput.contents()).andReturn("abcdefg");
      expect(crypto.cipher("RSA/NONE/OAEPPadding")).andReturn(cipher);
      
      replay(api, instanceApi, operation, serialPortOutput);

      WindowsPasswordGenerator generator = new WindowsPasswordGenerator(api, bcCrypto, operationDone);
      String result = generator.apply(new AtomicReference<Instance>(instance));

      verify(api, instanceApi, operation, serialPortOutput);
      assertEquals(result, "pa55w0rd");
   }
}

