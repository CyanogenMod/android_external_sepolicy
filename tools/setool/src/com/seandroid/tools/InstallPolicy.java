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
