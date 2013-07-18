/*
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.seandroid.tools;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.PrintStream;

import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

public class Package {

    private String mPackageName;
    private String mPolicyXml;
    private final PrintStream mWriter;

    private final Set<String> mUsesPerms = new HashSet<String>(10);
    private final Set<String> mX509Certs = new HashSet<String>(2);

    private static final String AAPT_CMD = "aapt d permissions";
    private static final String AAPT_PACKAGE = "package:";
    private static final String AAPT_USES_PERMISSION = "uses-permission:";

    private static final String ANDROID_MANIFEST_FILE = "AndroidManifest.xml";

    private static final PrintStream ERROR = System.err;

    // Split perms in JB and beyond.
    private static final HashMap<String, String> SPLIT_PERMS =
            new HashMap<String,String>(3);

    static {
        SPLIT_PERMS.put("android.permission.WRITE_EXTERNAL_STORAGE",
                        "android.permission.READ_EXTERNAL_STORAGE");

        SPLIT_PERMS.put("android.permission.READ_CONTACTS",
                        "android.permission.READ_CALL_LOG");

        SPLIT_PERMS.put("android.permission.WRITE_CONTACTS",
                        "android.permission.WRITE_CALL_LOG");
    }

    public Package(PrintStream output) {
        mWriter = output;
    }

    public void createPolicyEntry(String apk, String seinfo) {
        readCerts(apk);
        aapt(apk);
        mPolicyXml = PolicyBuilder.createAllowPermsStanza(mX509Certs, mUsesPerms,
                                                          mPackageName, seinfo);
        dumpPolicy();
    }

    public void createKeysOnly(String apk, String seinfo) {
        readCerts(apk);
        mPolicyXml = PolicyBuilder.createSignerOnlyStanza(mX509Certs, seinfo);
        dumpPolicy();
    }

    public void aapt(String apk) {

        String path = System.getenv("ANDROID_HOST_OUT");
        String CMD = AAPT_CMD;
        if (path == null) {
            ERROR.println("Warning. Might not find 'aapt' tool." +
                               " Try running 'lunch' command first.");
        } else {
            final String separator = System.getProperty("file.separator");
            CMD = path + separator + "bin" + separator + AAPT_CMD;
        }

        try {
            Process proc = Runtime.getRuntime().exec(CMD + " " + apk);

            InputStreamReader isr =
                new InputStreamReader(proc.getInputStream());

            BufferedReader in = new BufferedReader(isr);
            String line = null;
            while ((line = in.readLine()) != null) {
                if (line.startsWith(AAPT_PACKAGE)) {
                    mPackageName = line.substring(AAPT_PACKAGE.length() + 1);
                } else if (line.startsWith(AAPT_USES_PERMISSION)) {
                    int spot = AAPT_USES_PERMISSION.length() + 1;
                    mUsesPerms.add(line.substring(spot));
                }
            }

            for (String perm : SPLIT_PERMS.keySet()) {
                if (mUsesPerms.contains(perm)) {
                    mUsesPerms.add(SPLIT_PERMS.get(perm));
                }
            }

        } catch (IOException e) {
            ERROR.println("Had trouble with 'aapt' process. Results for " +
                               apk + " questionable: " + e.toString());
        }
    }


    public void readCerts(String apk) {

        try {
            JarFile jarFile = new JarFile(apk);
            JarEntry jarEntry = jarFile.getJarEntry(ANDROID_MANIFEST_FILE);

            byte[] readBuffer = new byte[8192];

            InputStream is =
                new BufferedInputStream(jarFile.getInputStream(jarEntry));

            while (is.read(readBuffer, 0, readBuffer.length) != -1) {
                ; // we only read to get to the cert
            }
            is.close();

            Certificate[] certs = jarEntry.getCertificates();
            if (certs == null) {
                System.err.println("No certs found for " + apk);
                return;
            }

            for (Certificate cert : certs) {
                byte sigs[] = cert.getEncoded();
                int N = sigs.length;
                final int N2 = N*2;
                char[] text = new char[N2];
                for (int j=0; j<N; j++) {
                    byte v = sigs[j];
                    int d = (v >> 4) & 0xf;
                    text[j*2] = (char)(d >= 10 ? ('a' + d-10) : ('0' + d));
                    d = v & 0xf;
                    text[j*2 + 1] = (char)(d >= 10 ? ('a' + d-10) : ('0' + d));
                }
                mX509Certs.add(new String(text));
            }
            jarFile.close();
        } catch (IOException e) {
            ERROR.println("Had trouble extracting certs. Results for " +
                               apk + " questionable: " + e.toString());
        } catch (CertificateEncodingException e) {
            ERROR.println("Had trouble extracting certs. Results for " +
                               apk + " questionable: " + e.toString());
        }
    }

    public Set<String> getCerts() {
        return mX509Certs;
    }

    public Set<String> getPerms() {
        return mUsesPerms;
    }

    public String getPackageName() {
        return mPackageName;
    }

    private void dumpPolicy() {
        mWriter.println(mPolicyXml);
    }
}
