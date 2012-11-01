package com.seandroid.tools;

import junit.framework.Test;
import junit.framework.TestSuite;

import junit.textui.TestRunner;

public class AllTests extends TestSuite {

    public static Test suite() {
        TestSuite suite = new TestSuite("setool tests");
        suite.addTestSuite(PolicyBuilderTest.class);
        suite.addTestSuite(PolicyParserTest.class);
        suite.addTestSuite(UsageTest.class);
        return suite;
    }
} 