/*
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License v2.0 which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-v20.html
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Copyright Contributors to the Zowe Project.
 */
package com.ca.mfaas.gateway.security.pkcs11;

import lombok.extern.slf4j.Slf4j;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Enumeration;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

@Slf4j
public class PKCS11Test {

    private static final String PIN = "password";

    @Test
    public void testLocalPkcs11() {
        String configFileName = "pkcs11.cfg";
        // Get the un-initialized IBMPKCS11Impl provider
        Provider provider = Security.getProvider("IBMPKCS11Impl");
        try {
            // Create a PKCS#11 session and initialize it
            // using the pkcs11.cfg PKCS#11
            // configuration file
            URL configUrl = ClassLoader.getSystemClassLoader().getResource(configFileName);
            if (configUrl != null) {
                File configFile = new File(configUrl.getPath());
                ((com.ibm.crypto.pkcs11impl.provider.IBMPKCS11Impl)provider).Init(configFile.getAbsolutePath(), PIN.toCharArray());
                 /*//Alternative way to initialize provider
                 provider = new com.ibm.crypto.pkcs11impl.provider.IBMPKCS11Impl(configFile.getAbsolutePath());
                 provider.login();
                 Security.addProvider(provider);*/
            }
        } catch (Exception ex) {
            log.error("Error in initialization of PKCS11 provider.", ex);
            fail();
            return;
        }
        if (provider != null) {
            KeyStore ks = loadKeyStore("PKCS11IMPLKS", provider);
            if (ks != null) {
                Key key = loadKey(ks,"localhost");
                if (key != null) {
                    String secretKey = Base64.getEncoder().encodeToString(key.getEncoded());
                    System.out.println(secretKey);
                    assertFalse(secretKey.trim().isEmpty());
                } else {
                    fail();
                }
            }
            // Remove and close the PKCS#11 session for
            // IBMPKCS11Impl
            ((com.ibm.crypto.pkcs11impl.provider.IBMPKCS11Impl)provider).removeSession();
        }

    }

    private KeyStore loadKeyStore(String keyStoreType, Provider provider) {
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance("PKCS11IMPLKS", provider);
            ks.load(null, PIN.toCharArray());
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException ex) {
            log.error("Error in loading key store.", ex);
        }
        return ks;
    }

    private Key loadKey(KeyStore keyStore, String keyAlias) {
        Key key = null;
        try {
            if (keyAlias != null) {
                key = keyStore.getKey(keyAlias, PIN.toCharArray());
            } else {
                for (Enumeration<String> e = keyStore.aliases(); e.hasMoreElements(); ) {
                    String alias = e.nextElement();
                    try {
                        key = keyStore.getKey(alias, PIN.toCharArray());
                        break;
                    } catch (UnrecoverableKeyException uke) {
                        log.debug("Key with alias {} could not be used: {}", alias, uke.getMessage());
                    }
                }
            }
        } catch (Exception ex) {
            log.error("Error in loading key.", ex);
        }
        return key;
    }
}
