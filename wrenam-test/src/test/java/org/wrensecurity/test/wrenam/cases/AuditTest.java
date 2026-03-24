/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.1.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.1.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2026 Wren Security
 */

package org.wrensecurity.test.wrenam.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.wrensecurity.test.base.support.CustomAssertions.assertSuccess;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.testcontainers.containers.Container.ExecResult;
import org.wrensecurity.test.wrenam.base.WrenAMClient;
import org.wrensecurity.test.wrenam.base.WrenAMClient.AuthenticationHandler;
import org.wrensecurity.test.wrenam.base.WrenAMCommands;
import org.wrensecurity.test.wrenam.base.WrenAMDefaults;
import org.wrensecurity.test.wrenam.base.WrenAMTestBase;

@TestInstance(Lifecycle.PER_CLASS)
public class AuditTest extends WrenAMTestBase {

    private static final String AUTH_LOG_PATH = "/srv/wrenam/auth/log/authentication.csv";

    @BeforeAll
    public void setupAuditService() throws Exception {
        ExecResult result = WrenAMCommands.ssoadm(
                wrenam1,
                "set-sub-cfg",
                "--servicename", "AuditService",
                "--subconfigname", "Global CSV Handler",
                "--operation", "set",
                "--attributevalues", "bufferingEnabled=false", "bufferingAutoFlush=true");
        assertSuccess(result, "Unable to disable audit service buffering");
    }

    @Test
    public void testSuccessfulAuthAudit() throws Exception {
        WrenAMClient wrenamClient = wrenam1.getWrenAMClient();

        long linesBefore = readFileLineCount(AUTH_LOG_PATH);

        AuthenticationHandler authHandler = wrenamClient.authenticate()
                .immediateAuth(WrenAMDefaults.ADMIN_USERNAME, WrenAMDefaults.ADMIN_PASSWORD);
        assertTrue(authHandler.isSucceeded());

        List<String> increment = readFileLineIncrement(AUTH_LOG_PATH, linesBefore);
        assertEquals(2, increment.size(), "Increment of two log events (module and chain) expected");
        assertTrue(increment.get(0).matches(".*\"AM-LOGIN-MODULE-COMPLETED\".*\"SUCCESSFUL\".*"));
        assertTrue(increment.get(1).matches(".*\"AM-LOGIN-COMPLETED\".*\"SUCCESSFUL\".*"));
    }

    @Test
    public void testFailedAuthAudit() throws Exception {
        WrenAMClient wrenamClient = wrenam1.getWrenAMClient();

        long linesBefore = readFileLineCount(AUTH_LOG_PATH);

        AuthenticationHandler authHandler = wrenamClient.authenticate()
                .immediateAuth(WrenAMDefaults.ADMIN_USERNAME, "wrong_password");
        assertTrue(authHandler.isFailed());

        List<String> increment = readFileLineIncrement(AUTH_LOG_PATH, linesBefore);
        assertEquals(2, increment.size(), "Increment of two log events (module and chain) expected");
        assertTrue(increment.get(0).matches(".*\"AM-LOGIN-MODULE-COMPLETED\".*\"FAILED\".*"));
        assertTrue(increment.get(1).matches(".*\"AM-LOGIN-COMPLETED\".*\"FAILED\".*"));
    }

    private long readFileLineCount(String filename)
            throws UnsupportedOperationException, IOException, InterruptedException {
        ExecResult result = wrenam1.execInContainer("wc", "-l", filename);
        assertSuccess(result, "Unable to get audit log file line count");
        return Long.parseLong(result.getStdout().trim().split(" ")[0]);
    }

    private List<String> readFileLineIncrement(String filename, long linesAfter)
            throws UnsupportedOperationException, IOException, InterruptedException {
        ExecResult result = wrenam1.execInContainer("tail", "-n", "+" + (linesAfter + 1), filename);
        assertSuccess(result, "Unable to read audit log file lines");
        return !result.getStdout().isBlank()
                ? Arrays.asList(result.getStdout().split("\n"))
                : Collections.emptyList();
    }

}
