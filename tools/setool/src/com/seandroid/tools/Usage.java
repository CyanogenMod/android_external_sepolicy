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

import java.io.PrintStream;

public class Usage {

    private static final int MAX_LINE_WIDTH = 78;

    public static final String TOOL        = "setool";
    public static final String MAC_FILE    = "mac_permissions.xml";
    public static final String KEYS_TAG    = "keys";
    public static final String ENTRY_WHITE = "whitelist";
    public static final String HELP        = "--help";
    public static final String BUILD       = "--build";
    public static final String APKDIR      = "--apkdir";
    public static final String POLICYFILE  = "--policy";
    public static final String SEINFO      = "--seinfo";
    public static final String OUTFILE     = "--outfile";
    public static final String VERBOSE     = "--verbose";

    public static void printUsage(PrintStream out) {
        out.println("Usage: " + TOOL + " [flags] <--build|--policy> <apks>\n");
        out.println("Tool to help build and verify MMAC install policies.\n");
        printUsage(out, new String[] {
                "apks", "List of apks to analyze, space separated. All " +
                "supplied apks must be absolute paths or relative to " + APKDIR +
                " (which defaults to the current directory).",
                "", "\n",
                BUILD, "Generate an MMAC style policy stanza. The resulting " +
                "stanza can then be used as an entry in the " + MAC_FILE + " file.",
                "\t" + ENTRY_WHITE, "\nPolicy entry that contains a white listing " +
                "of all permissions. The stanza will contain the app's package tag " +
                "within its signer tag.",
                "\t" + KEYS_TAG, "\nPrint a valid signer tag which contains the " +
                "hex encoded X.509 cert of the app.",
                "", "\n",
                POLICYFILE, "Determine if supplied apks pass the supplied policy."
            });

        out.println("\n\nFlags:\n");
        printUsage(out, new String[] {
                HELP, "Prints this message and exits.",
                APKDIR, "Directory to search for supplied apks (default to current directory).",
                VERBOSE, "Increase the amount of debug statements.",
                OUTFILE, "Dump all output to the given file (defaults to stdout).",
                SEINFO, "Create an seinfo tag for all generated policy stanzas.",
            });
        out.println("\n");
    }


    private static void printUsage(PrintStream out, String[] args) {
        int argWidth = 0;
        for (int i = 0; i < args.length; i += 2) {
            String arg = args[i];
            argWidth = Math.max(argWidth, arg.length());
        }
        argWidth += 2;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < argWidth; i++) {
            sb.append(' ');
        }
        String indent = sb.toString();
        String formatString = "%1$-" + argWidth + "s%2$s";

        for (int i = 0; i < args.length; i += 2) {
            String arg = args[i];
            String description = args[i + 1];
            if (arg.length() == 0) {
                out.println(description);
            } else {
                out.print(wrap(String.format(formatString, arg, description),
                               MAX_LINE_WIDTH, indent));
            }
        }
    }


    static String wrap(String explanation, int lineWidth, String hangingIndent) {
        int explanationLength = explanation.length();
        StringBuilder sb = new StringBuilder(explanationLength * 2);
        int index = 0;

        while (index < explanationLength) {
            int lineEnd = explanation.indexOf('\n', index);
            int next;

            if (lineEnd != -1 && (lineEnd - index) < lineWidth) {
                next = lineEnd + 1;
            } else {
                // Line is longer than available width; grab as much as we can
                lineEnd = Math.min(index + lineWidth, explanationLength);
                if (lineEnd - index < lineWidth) {
                    next = explanationLength;
                } else {
                    // then back up to the last space 
                    int lastSpace = explanation.lastIndexOf(' ', lineEnd);
                    if (lastSpace > index) {
                        lineEnd = lastSpace;
                        next = lastSpace + 1;
                    } else {
                        // No space anywhere on the line: it contains something wider than
                        // can fit (like a long URL) so just hard break it
                        next = lineEnd + 1;
                    }
                }
            }

            if (sb.length() > 0) {
                sb.append(hangingIndent);
            } else {
                lineWidth -= hangingIndent.length();
            }

            sb.append(explanation.substring(index, lineEnd));
            sb.append('\n');
            index = next;
        }

        return sb.toString();
    }
}