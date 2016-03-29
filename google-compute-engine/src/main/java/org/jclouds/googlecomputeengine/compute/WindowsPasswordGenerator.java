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
package org.jclouds.googlecomputeengine.compute;

import com.google.common.io.BaseEncoding;
import com.google.gson.Gson;
import org.jclouds.domain.LoginCredentials;
import org.jclouds.googlecomputeengine.domain.Metadata;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.KeyFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.HashMap;
import java.util.TimeZone;

/**
 * Reference: https://github.com/GoogleCloudPlatform/compute-image-windows/blob/master/examples/windows_auth_java_sample.java
 */
public class WindowsPasswordGenerator {
    public String decryptPassword(String message, KeyPair keys) {
        try {
            // Add the bouncycastle provider - the built-in providers don't support RSA
            // with OAEPPadding.
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            // Get the appropriate cipher instance.
            Cipher rsa = Cipher.getInstance("RSA/NONE/OAEPPadding", "BC");

            // Add the private key for decryption.
            rsa.init(Cipher.DECRYPT_MODE, keys.getPrivate());

            // Decrypt the text.
            byte[] rawMessage = Base64.getDecoder().decode(message);
            byte[] decryptedText = rsa.doFinal(rawMessage);

            // The password was encoded using UTF8. Transform into string.
            return new String(decryptedText, "UTF8");
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
        return "";
    }


    public KeyPair generateKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");

        // Key moduli for encryption/decryption are 2048 bits long.
        keyGen.initialize(2048);

        return keyGen.genKeyPair();
    }

    public void replaceMetadata(Metadata input, Map<String, String> newMetadataItem) {
        // Replace item's value with the new entry.
        // To prevent race conditions, production code may want to maintain a
        // list where the oldest entries are removed once the 32KB limit is
        // reached for the metadata entry.
        input.put("windows-keys", new Gson().toJson(newMetadataItem));
    }

    // Keys are one-time use, so the metadata doesn't need to stay around for long.
    // 5 minutes chosen to allow for differences between time on the client
    // and time on the server.
    private static final long EXPIRE_TIME = 300000;

    public Map<String, String> buildKeyMetadata(KeyPair pair) throws NoSuchAlgorithmException,
            InvalidKeySpecException {
        // Object used for storing the metadata values.
        HashMap<String, String> metadataValues = new HashMap<String, String>();

        // Encode the public key into the required JSON format.
        metadataValues.putAll(jsonEncode(pair));

        // Add username and email.
//      metadataValues.put("userName", USER_NAME);
//      metadataValues.put("email", EMAIL);

        // Create the date on which the new keys expire.
        Date now = new Date();
        Date expireDate = new Date(now.getTime() + EXPIRE_TIME);

        // Format the date to match rfc3339.
        SimpleDateFormat rfc3339Format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        rfc3339Format.setTimeZone(TimeZone.getTimeZone("UTC"));
        String dateString = rfc3339Format.format(expireDate);

        // Encode the expiration date for the returned JSON dictionary.
        metadataValues.put("expireOn", dateString);

        return metadataValues;
    }

    private HashMap<String,String> jsonEncode(KeyPair keys) throws NoSuchAlgorithmException,
            InvalidKeySpecException {
        KeyFactory factory = KeyFactory.getInstance("RSA");

        // Get the RSA spec for key manipulation.
        RSAPublicKeySpec pubSpec = factory.getKeySpec(keys.getPublic(), RSAPublicKeySpec.class);

        // Extract required parts of the key.
        BigInteger modulus = pubSpec.getModulus();
        BigInteger exponent = pubSpec.getPublicExponent();

        // Grab an encoder for the modulus and exponent to encode using RFC 3548;
        // Java SE 7 requires an external library (Google's Guava used here)
        // Java SE 8 has a built-in Base64 class that can be used instead. Apache also has an RFC 3548
        // encoder.
        BaseEncoding stringEncoder = BaseEncoding.base64();

        // Strip out the leading 0 byte in the modulus.
        byte[] arr = Arrays.copyOfRange(modulus.toByteArray(), 1, modulus.toByteArray().length);

        HashMap<String,String> returnJson = new HashMap<String,String>();

        // Encode the modulus, add to returned JSON object.
        String modulusString = stringEncoder.encode(arr).replaceAll("\n", "");
        returnJson.put("modulus", modulusString);

        // Encode exponent, add to returned JSON object.
        String exponentString = stringEncoder.encode(exponent.toByteArray()).replaceAll("\n", "");
        returnJson.put("exponent", exponentString);

        return returnJson;
    }

    public LoginCredentials credentialsWithNewPassword(LoginCredentials credentials, String password) {
        LoginCredentials.Builder result = LoginCredentials.builder();
        result.user(credentials.getUser());
        result.privateKey(credentials.getOptionalPrivateKey().get());
        result.authenticateSudo(credentials.shouldAuthenticateSudo());

        result.password(password);
        return result.build();
    }
}
