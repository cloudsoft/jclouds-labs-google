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

import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;
import java.util.TimeZone;
import java.util.concurrent.atomic.AtomicReference;

import javax.annotation.Resource;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.inject.Inject;
import javax.inject.Named;

import org.jclouds.compute.reference.ComputeServiceConstants;
import org.jclouds.crypto.Crypto;
import org.jclouds.googlecomputeengine.GoogleComputeEngineApi;
import org.jclouds.googlecomputeengine.domain.Instance;
import org.jclouds.googlecomputeengine.domain.Instance.SerialPortOutput;
import org.jclouds.googlecomputeengine.domain.Metadata;
import org.jclouds.googlecomputeengine.domain.Operation;
import org.jclouds.googlecomputeengine.features.InstanceApi;
import org.jclouds.logging.Logger;

import com.google.common.base.Function;
import com.google.common.base.Predicate;
import com.google.common.base.Splitter;
import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Iterables;
import com.google.common.io.BaseEncoding;
import com.google.common.util.concurrent.Atomics;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.google.inject.TypeLiteral;

/**
 * References:
 * <ul>
 *   <li>{@linkplain https://cloud.google.com/compute/docs/instances/automate-pw-generation}
 *   <li>{@linkplain https://github.com/GoogleCloudPlatform/compute-image-windows/blob/master/examples/windows_auth_java_sample.java}
 * </ul>
 * 
 * In brief, the sequence is:
 * <ol>
 *   <li>Generate a temporary key for encrypting and decrypting the password
 *   <li>Send the RSA public key to the instance, by settings its metadata
 *   <li>Retrieve the result from the {@link SerialPortOutput}
 *   <li>Decode and decrypt the result.
 * </ol>
 */
public class WindowsPasswordGenerator implements Function<AtomicReference<Instance>, String> {

   /**
    * Indicates when the key should expire. Keys are one-time use, so the metadata doesn't need to stay around for long.
    * 5 minutes chosen to allow for differences between time on the client
    * and time on the server.
    */
   private static final long EXPIRE_DURATION = 30 * 60 * 1000;

   @Resource
   @Named(ComputeServiceConstants.COMPUTE_LOGGER)
   protected Logger logger = Logger.NULL;

   private final GoogleComputeEngineApi api;
   private final Crypto crypto;
   private final Predicate<AtomicReference<Operation>> operationDone;
   
   @Inject
   protected WindowsPasswordGenerator(GoogleComputeEngineApi api, Crypto crypto, Predicate<AtomicReference<Operation>> operationDone) {
      this.api = api;
      this.crypto = crypto;
      this.operationDone = operationDone;
   }

   @Override
   public String apply(AtomicReference<Instance> instance) {
      // FIXME get zone how?
      String zone;
      //zoneUri = instance.get().zone();
      zone = "us-central1-a";

      // TODO Check whether VM is up
      try {
         // Generate the public/private key pair for encryption and decryption.
         // TODO do we need to explicitly set 2048 bits? Presumably "RSA" is implicit
         KeyPair keys = crypto.rsaKeyPairGenerator().genKeyPair();

         // Update instance's metadata with new "windows-keys" entry, and wait for operation to 
         // complete.
         logger.debug("Generating windows key for instance %s, by updating metadata", instance.get().id());
         InstanceApi instanceApi = api.instancesInZone(zone);
         Metadata metadata = instance.get().metadata();
         metadata.put("windows-keys", new Gson().toJson(extractKeyMetadata(keys)));

         AtomicReference<Operation> operation = Atomics.newReference(instanceApi.setMetadata(instance.get().id(), metadata));
         operationDone.apply(operation);

         if (operation.get().httpErrorStatusCode() != null) {
            logger.warn("Generating windows key for %s failed. Http Error Code: %d HttpError: %s",
                  operation.get().targetId(), operation.get().httpErrorStatusCode(),
                  operation.get().httpErrorMessage());
         }

         // Retrieve the result from the last line of serialPortOutput; expect JSON string
         // FIXME should it be "\\n", as Valentin did?
         Instance.SerialPortOutput serialPortOutput = instanceApi.getSerialPortOutput(instance.get().id(), 4);
         String entry = Iterables.getLast(Splitter.on("\n").split(serialPortOutput.contents()));

         // Decrypt and return the password
         // FIXME Use TypeToken
         Map<String, String> passwordDict = new Gson().fromJson(entry, Map.class);
         return checkNotNull(passwordDict.get("encryptedPassword"), "password");

      } catch (NoSuchAlgorithmException e) {
         throw Throwables.propagate(e);
      } catch (InvalidKeySpecException e) {
         throw Throwables.propagate(e);
      }
   }

   /**
    * Decrypts the given password - the encrypted text is base64-encoded.
    * As per the GCE docs, assumes it was encrypted with algorithm "RSA/NONE/OAEPPadding", and UTF-8.
 * @throws NoSuchPaddingException 
 * @throws NoSuchAlgorithmException 
 * @throws InvalidKeyException 
 * @throws BadPaddingException 
 * @throws IllegalBlockSizeException 
    */
   protected String decryptPassword(String message, KeyPair keys) throws NoSuchAlgorithmException, 
   			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
      // FIXME how to ensure crypto supports OAEPPadding?
      // FIXME Valentin's code was also passing provider "BC"
      // Assumes user has configured appropriate crypto guice module.
      Cipher cipher = crypto.cipher("RSA/NONE/OAEPPadding");

      // Add the private key for decryption.
      cipher.init(Cipher.DECRYPT_MODE, keys.getPrivate());

      // Decrypt the text.
      byte[] rawMessage = BaseEncoding.base64().decode(message);
      byte[] decryptedText = cipher.doFinal(rawMessage);

      // The password was encoded using UTF8. Transform into string.
      return new String(decryptedText, Charset.forName("UTF-8"));
   }

   /**
    * Generates the metadata value for this keypair.
    * Extracts the public key's the RSA spec's modulus and exponent, encoded as Base-64, and 
    * an expires date.
    * 
    * @param pair
    * @return
    * @throws NoSuchAlgorithmException
    * @throws InvalidKeySpecException
    */
   protected Map<String, String> extractKeyMetadata(KeyPair pair) throws NoSuchAlgorithmException, InvalidKeySpecException {
      KeyFactory factory = crypto.rsaKeyFactory();
      RSAPublicKeySpec pubSpec = factory.getKeySpec(pair.getPublic(), RSAPublicKeySpec.class);
      BigInteger modulus = pubSpec.getModulus();
      BigInteger exponent = pubSpec.getPublicExponent();

      // Strip out the leading 0 byte in the modulus.
      byte[] modulusArr = Arrays.copyOfRange(modulus.toByteArray(), 1, modulus.toByteArray().length);
      String modulusString = BaseEncoding.base64().encode(modulusArr).replaceAll("\n", "");
      String exponentString = BaseEncoding.base64().encode(exponent.toByteArray()).replaceAll("\n", "");

      // Create the expire date, formatted as rfc3339
      Date expireDate = new Date(System.currentTimeMillis() + EXPIRE_DURATION);
      SimpleDateFormat rfc3339Format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
      rfc3339Format.setTimeZone(TimeZone.getTimeZone("UTC"));
      String expireString = rfc3339Format.format(expireDate);

      return ImmutableMap.<String, String>builder()
            .put("modulus", modulusString)
            .put("exponent", exponentString)
            .put("expireOn", expireString)
            .build();
   }
}
