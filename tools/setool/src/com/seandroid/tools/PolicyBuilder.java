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

import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;

public class PolicyBuilder {

    static final String POLICY           = "policy";
    static final String ALLOW_ALL        = "allow-all";
    static final String ALLOW_PERMS      = "allow-permission";
    static final String DEFAULT          = "default";
    static final String DENY_PERMS       = "deny-permission";
    static final String NAME_ATTR        = "name";
    static final String PACKAGE          = "package";
    static final String SEINFO           = "seinfo";
    static final String SIGNER           = "signer";
    static final String SIGNATURE_ATTR   = "signature";
    static final String VALUE_ATTR       = "value";

    private static final String HEADER_XML =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";

    private static final String XML_END_TAG = " >\n";
    private static final String XML_END_TAG_ATTRIBUTE = "\">\n";
    private static final String XML_NO_CHILD_END_TAG = " />\n";
    private static final String XML_NO_CHILD_END_TAG_ATTR = "\" />\n";
    private static final String INDENT_ONE = "  ";
    private static final String INDENT_TWO = "    ";

    private static final String SIGNER_TAG_START;
    private static final String SIGNER_TAG_END;
    private static final String ALLOW_PERM_TAG_START;
    private static final String DENY_PERM_TAG_START;
    private static final String PACKAGE_TAG_START;
    private static final String PACKAGE_TAG_END;
    private static final String SEINFO_TAG_START;
    private static final String ALLOW_ALL_TAG;
    private static final String DEFAULT_TAG_START;
    private static final String DEFAULT_TAG_END;

    static final String ALLOW_TAG_ERROR;
    static final String DENY_TAG_ERROR;
    static final String SEINFO_TAG_ERROR;
    static final String SIGNER_TAG_ERROR;
    static final String PACKAGE_TAG_ERROR;

    static {
        ALLOW_TAG_ERROR = "<" + ALLOW_PERMS + "> without valid " + NAME_ATTR + " attribute.";
        DENY_TAG_ERROR  = "<" + DENY_PERMS  + "> without valid " + NAME_ATTR + " attribute.";
        SEINFO_TAG_ERROR = "<" + SEINFO + "> without valid " + VALUE_ATTR + " attribute.";
        SIGNER_TAG_ERROR = "<" + SIGNER + "> without valid " + SIGNATURE_ATTR + " attribute.";
        PACKAGE_TAG_ERROR = "<" + PACKAGE + "> without valid " + NAME_ATTR + " attribute.";

        SIGNER_TAG_START = "<" + SIGNER + " " + SIGNATURE_ATTR + "=\"";

        SIGNER_TAG_END = "</" + SIGNER + ">\n";

        ALLOW_PERM_TAG_START = "<" + ALLOW_PERMS + " " + NAME_ATTR + "=\"";

        DENY_PERM_TAG_START = "<" + DENY_PERMS + " " + NAME_ATTR + "=\"";

        PACKAGE_TAG_START = "<" + PACKAGE + " " + NAME_ATTR + "=\"";

        PACKAGE_TAG_END = "</" + PACKAGE + ">\n";

        SEINFO_TAG_START = "<" + SEINFO + " " + VALUE_ATTR + "=\"";

        ALLOW_ALL_TAG = "<" + ALLOW_ALL + " />\n";

        DEFAULT_TAG_START = "<" + DEFAULT + ">\n";

        DEFAULT_TAG_END = "</" + DEFAULT + ">\n";
    }

    private static final String signerTag(String x509) {
        StringBuilder str = new StringBuilder(SIGNER_TAG_START);
        str.append(x509);
        str.append(XML_END_TAG_ATTRIBUTE);
        return str.toString();
    }

    private static final String seinfoTag(String value) {
        StringBuilder str = new StringBuilder(SEINFO_TAG_START);
        str.append(value);
        str.append(XML_NO_CHILD_END_TAG_ATTR);
        return str.toString();
    }

    private static final String allowAllTag() {
        return ALLOW_ALL_TAG;
    }

    private static final Set<String> allowPermsTags(Set<String> perms) {

        Set<String> xmlPerms = new HashSet<String>(perms.size());
        for (String perm: perms) {
            StringBuilder str = new StringBuilder(ALLOW_PERM_TAG_START);
            str.append(perm);
            str.append(XML_NO_CHILD_END_TAG_ATTR);
            xmlPerms.add(str.toString());
        }
        return xmlPerms;
    }

    private static final String packageTag(String name) {
        StringBuilder str = new StringBuilder(PACKAGE_TAG_START);
        str.append(name);
        str.append(XML_END_TAG_ATTRIBUTE);
        return str.toString();
    }

    private static final Set<String> denyPermsTags(Set<String> perms) {

        Set<String> xmlPerms = new HashSet<String>(perms.size());
        for (String perm: perms) {
            StringBuilder str = new StringBuilder(DENY_PERM_TAG_START);
            str.append(perm);
            str.append(XML_NO_CHILD_END_TAG_ATTR);
            xmlPerms.add(str.toString());
        }
        return xmlPerms;
    }

    private static final String defaultTag() {
        return DEFAULT_TAG_START;
    }

    public static final String createSignerOnlyStanza(Set<String> x509, String seinfo) {
        StringBuilder ret = new StringBuilder();
        for (String sig : x509) {
            ret.append(signerTag(sig));
            if (seinfo != null) {
                ret.append(INDENT_ONE + seinfoTag(seinfo));
            }
            ret.append(SIGNER_TAG_END);
        }
        return ret.toString();
    }

    public static final String createAllowPermsStanza(Set<String> x509, Set<String> perms,
                                                      String name, String seinfo) {
        Set<String> tags = new TreeSet<String>(allowPermsTags(perms));
        StringBuilder ret = new StringBuilder();
        for (String sig : x509) {
            ret.append(signerTag(sig));
            ret.append(INDENT_ONE + packageTag(name));
            for (String tag : tags) {
                ret.append(INDENT_TWO + tag);
            }
            if (seinfo != null) {
                ret.append(INDENT_TWO + seinfoTag(seinfo));
            }
            ret.append(INDENT_ONE + PACKAGE_TAG_END);
            ret.append(SIGNER_TAG_END);
        }
        return ret.toString();
    }

    public static final String createDenyPermsStanza(Set<String> x509, Set<String> perms) {
        Set<String> tags = denyPermsTags(perms);
        StringBuilder ret = new StringBuilder();
        for (String sig : x509) {
            ret.append(signerTag(sig));
            for (String tag : tags) {
                ret.append(INDENT_ONE + tag);
            }
            ret.append(SIGNER_TAG_END);
        }
        return ret.toString();
    }

    public static final String createAllowAllStanza(Set<String> x509) {
        StringBuilder ret = new StringBuilder();
        for (String sig : x509) {
            ret.append(signerTag(sig) + allowAllTag() + SIGNER_TAG_END);
        }
        return ret.toString();
    }
}
