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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.TreeSet;

/**
 * Base class for all install policy classes.
 * Also doubles as the wildcard (allow everything) policy.
 */
public class InstallPolicy {

    final HashSet<String> policyPerms;
    final HashMap<String, InstallPolicy> packagePolicy;
    String policyError;

    InstallPolicy(HashSet<String> policyPerms, HashMap<String, InstallPolicy> packagePolicy) {
        this.policyPerms = policyPerms;
        this.packagePolicy = packagePolicy;
    }

    public boolean passedPolicyChecks(String packageName, Set<String> perms) {
        if (packagePolicy.containsKey(packageName)) {
            boolean passed = packagePolicy.get(packageName).passedPolicyChecks(packageName, perms);
            if (!passed) {
                policyError = packagePolicy.get(packageName).policyError;
            }
        }
        return true;
    }

    public String toString() {
        StringBuilder out = new StringBuilder();
        for (String perm : new TreeSet<String>(policyPerms)) {
            out.append("\n").append(perm);
        }
        out.append("\n");
        return out.toString();
    }
}

/**
 * Whitelist policy class. Checks that the set of requested permissions
 * is a subset of the maximal set of allowable permissions.
 */
class WhiteListPolicy extends InstallPolicy {

    WhiteListPolicy(HashSet<String> policyPerms, HashMap<String, InstallPolicy> packagePolicy) {
        super(policyPerms, packagePolicy);
    }

    @Override
    public boolean passedPolicyChecks(String packageName, Set<String> perms) {
        if (packagePolicy.containsKey(packageName)) {
            boolean passed = packagePolicy.get(packageName).passedPolicyChecks(packageName, perms);
            if (!passed) {
                policyError = packagePolicy.get(packageName).policyError;
            }
            return passed;
        }

        Iterator itr = perms.iterator();
        while (itr.hasNext()) {
            String perm = (String)itr.next();
            if (!policyPerms.contains(perm)) {
                policyError = "Policy whitelist rejected package " +
                    packageName + "\nUnapproved permission " +
                    perm + "\nThe maximal set is: " + toString();
                return false;
            }
        }
        return true;
    }
}

/**
 * Blacklist policy class. Ensures that all requested permissions
 * are not on the denied list of permissions.
 */
class BlackListPolicy extends InstallPolicy {

    BlackListPolicy(HashSet<String> policyPerms, HashMap<String, InstallPolicy> packagePolicy) {
        super(policyPerms, packagePolicy);
    }

    @Override
    public boolean passedPolicyChecks(String packageName, Set<String> perms) {
        if (packagePolicy.containsKey(packageName)) {
            boolean passed = packagePolicy.get(packageName).passedPolicyChecks(packageName, perms);
            if (!passed) {
                policyError = packagePolicy.get(packageName).policyError;
            }
            return passed;
        }

        Iterator itr = perms.iterator();
        while (itr.hasNext()) {
            String perm = (String)itr.next();
            if (policyPerms.contains(perm)) {
                policyError = "Policy blacklist rejected package " +
                    packageName + "\nDenied permission " + perm +
                    "\nSet of blacklisted permissions is: " + toString();
                return false;
            }
        }
        return true;
    }
}

class DenyPolicy extends InstallPolicy {

    DenyPolicy(HashSet<String> policyPerms, HashMap<String, InstallPolicy> packagePolicy) {
        super(policyPerms, packagePolicy);
    }

    @Override
    public boolean passedPolicyChecks(String packageName, Set<String> perms) {
        if (packagePolicy.containsKey(packageName)) {
            boolean passed =  packagePolicy.get(packageName).passedPolicyChecks(packageName, perms);
            if (!passed) {
                policyError = packagePolicy.get(packageName).policyError;
            }
            return passed;
        }
        return false;
    }

    @Override
    public String toString() {
        return "deny-all";
    }
}
