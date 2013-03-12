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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;

import java.util.HashSet;
import java.util.Set;

public class Main {

    private static final String DOT_APK = ".apk";

    private static final int EXIT_ERROR   = 1;
    private static final int EXIT_SUCCESS = 0;

    private static boolean mPolicy   = false;
    private static boolean mVerbose  = false;
    private static boolean mBuildPolicy = false;

    private static PrintStream mOutput = System.out;
    private static final PrintStream ERROR = System.err;
    private static String mApkDirectory = ".";
    private static String mBuildType = Usage.KEYS_TAG;
    private static String mPolicyFile;
    private static String mSeinfo;

    private static Set<String> mApks = new HashSet<String>(5);
    private static Set<Package> mPackages = new HashSet<Package>(5);

    public Main() {
    }

    public static void main(String args[]) {
        new Main().run(args);
    }

    private static String getArg(String[] args, int index) {
        try {
            return args[index];
        } catch (ArrayIndexOutOfBoundsException e) {
            ERROR.println("Option " + args[index - 1] + " without a string.\n");
            Usage.printUsage(System.out);
            System.exit(EXIT_ERROR);
        }
        return null;
    }

    private void run(String[] args) {
        if (args.length < 1) {
            Usage.printUsage(System.err);
            System.exit(EXIT_ERROR);
        }

        for (int index = 0; index < args.length; index++) {
            String arg = args[index];

            if (Usage.HELP.equals(arg)) {
                Usage.printUsage(System.out);
                System.exit(EXIT_SUCCESS);
            } else if (Usage.BUILD.equals(arg)) {
                mBuildType = getArg(args, ++index);
                mBuildPolicy = true;
            } else if (Usage.APKDIR.equals(arg)) {
                mApkDirectory = getArg(args, ++index);
            } else if (Usage.SEINFO.equals(arg)) {
                mSeinfo = getArg(args, ++index);
            } else if (Usage.POLICYFILE.equals(arg)) {
                mPolicyFile = getArg(args, ++index);
                mPolicy = true;
            } else if (Usage.VERBOSE.equals(arg)) {
                mVerbose = true;
            } else if (Usage.OUTFILE.equals(arg)) {
                File out = new File(getArg(args, ++index));
                if (out.exists() && !out.canWrite()) {
                    ERROR.println(out.getPath() + ": Not writable. " +
                                       "Writing to stdout instead.");
                    continue;
                }
                try {
                    mOutput = new PrintStream(out);
                } catch (FileNotFoundException e) {
                    ERROR.println("Defaulting to stdout." + e.toString());
                }
            } else if (arg.startsWith("-")) {
                ERROR.println("Invalid argument " + arg + ".\n");
                Usage.printUsage(System.err);
                System.exit(EXIT_ERROR);
            } else {
                // Any piece not prefixed with '-' is considered an apk.
                // Make sure it sorta looks like an apk
                if (arg.endsWith(DOT_APK)) {
                    mApks.add(arg);
                } else {
                    ERROR.println(arg + ": Skipping. Doesn't end with '" +
                                  DOT_APK + "'\n");
                }
            }
        }

        // mutually exclusive options
        if (mPolicy && mBuildPolicy) {
            ERROR.println("Can only specify one of " + Usage.BUILD +
                          " or " + Usage.POLICYFILE);
            Usage.printUsage(System.out);
            System.exit(EXIT_ERROR);
        }

        // we need at least 1 apk to work with
        if (mApks.size() == 0) {
            ERROR.println("No apks to analyze. Exiting.");
            System.exit(EXIT_ERROR);
        }

        for (String apk : mApks) {
            File apk_file = new File(apk);
            if (!apk_file.isAbsolute()) {
                File file = new File(mApkDirectory, apk);
                if (!file.exists()) {
                    ERROR.println(file.getPath() + " doesn't exist. Skipping.");
                    continue;
                }
                apk = file.getPath();
            }
            Package app = new Package(mOutput);
            if (mBuildPolicy) {
                if (mBuildType.equals(Usage.ENTRY_WHITE)) {
                    app.createPolicyEntry(apk, mSeinfo);
                } else if (mBuildType.equals(Usage.KEYS_TAG)) {
                    app.createKeysOnly(apk, mSeinfo);
                } else {
                    ERROR.println("Didn't specify a valid " + Usage.BUILD + " option.");
                    Usage.printUsage(System.out);
                    System.exit(EXIT_ERROR);
                }
            } else if (mPolicy) {
                try {
                    PolicyParser.PolicyStart(new File(mPolicyFile));
                } catch (Exception e) {
                    ERROR.println(e.toString());
                    continue;
                }
                app.aapt(apk);
                app.readCerts(apk);
                Set<String> sigs = app.getCerts();
                Set<String> perms = app.getPerms();
                String name = app.getPackageName();
                String error = PolicyParser.passedPolicy(sigs, perms, name);
                if (error == null) {
                    ERROR.println("MMAC policy passed for " + name + " (" + apk + ").");
                } else {
                    ERROR.println("\n\nMMAC policy failed for " + name + " (" + apk + ").\n" +
                                  error);
                    System.exit(EXIT_ERROR);
                }
            } else {
                ERROR.println("Didn't specify a proper policy option.");
                Usage.printUsage(System.out);
                System.exit(EXIT_ERROR);
            }
        }
    }
}
