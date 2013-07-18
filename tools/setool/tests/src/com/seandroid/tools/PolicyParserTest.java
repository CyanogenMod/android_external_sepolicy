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
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;

import junit.framework.Assert;
import junit.framework.TestCase;

public class PolicyParserTest extends TestCase {

    public PolicyParserTest(String name) {
        super(name);
    }

    // Test if we can simply open and 'parse' a known good file
    public void testGoodFileOpen() {
        InputStream stream = this.getClass().getResourceAsStream("1.xml");
        String testMe = "";
        try {
            PolicyParser.PolicyStart(stream);
            testMe = "alls good";
        } catch (Exception e) {
            testMe = e.toString();
        }
        Assert.assertEquals("alls good", testMe);
    }

    // Test if we can't read a policy file
    public void testFileOpenCantRead() {
    }

    // Test if policy file doesn't exist
    public void testFileOpenDoesntExist() {
        InputStream stream = this.getClass().getResourceAsStream("doesntexist.xml");
        String testMe = "";
        try {
            PolicyParser.PolicyStart(stream);
            testMe = "good return";
        } catch (Exception e) {
            testMe = e.toString();
        }
        Assert.assertEquals("java.lang.IllegalArgumentException: InputStream cannot be null", testMe);
    }

    // Test if policy file has no <policy> root tag
    public void testNoPolicyStartTag() {
    }

    public void testMultiplePolicyStartTags() {
    }

    public void testMalformedXml() {
    }

    public void testOnlyPolicyTag() {
    }

    // test if bad signature att.
    // test if bad or missing package-name

} 