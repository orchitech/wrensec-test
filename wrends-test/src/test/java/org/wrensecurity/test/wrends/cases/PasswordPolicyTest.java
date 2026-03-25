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

package org.wrensecurity.test.wrends.cases;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.wrensecurity.test.wrends.base.WrenDSCommands.assertSuccess;
import static org.wrensecurity.test.wrends.base.WrenDSCommands.dsconfig;

import org.junit.jupiter.api.Test;
import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.wrensecurity.test.base.wrends.WrenDSContainer;

@Testcontainers
public class PasswordPolicyTest {

    @Container
    @SuppressWarnings("resource")
    private static WrenDSContainer wrends = new WrenDSContainer().withSampleData();

    @Test
    public void testCreatePasswordPolicy() throws Exception {
        // Verify the policy does not exist yet
        ExecResult checkResult = dsconfig(wrends,
                "get-password-policy-prop",
                "--policy-name", "Test Password Policy");
        assertNotEquals(0, checkResult.getExitCode(), "Should fail since the policy does not exist");

        // Create custom password policy
        ExecResult createResult = dsconfig(wrends,
                "create-password-policy",
                "--type", "password-policy",
                "--policy-name", "Test Password Policy",
                "--set", "password-attribute:userPassword",
                "--set", "default-password-storage-scheme:Salted SHA-1",
                "--set", "lockout-duration:300s",
                "--set", "lockout-failure-count:3",
                "--set", "password-change-requires-current-password:true");
        assertSuccess(createResult, "Failed to create password policy");

        // Verify the policy now exists
        ExecResult verifyResult = dsconfig(wrends,
                "get-password-policy-prop",
                "--policy-name", "Test Password Policy");
        assertSuccess(verifyResult, "Password policy should exist after creation");

        // TODO validate password policy enforcement
    }

}
