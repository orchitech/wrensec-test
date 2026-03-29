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
import static org.wrensecurity.test.base.support.CustomAssertions.assertSuccess;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.testcontainers.containers.Container.ExecResult;
import org.wrensecurity.test.wrenam.base.WrenAMCommands;
import org.wrensecurity.test.wrenam.base.WrenAMTestBase;

@TestInstance(Lifecycle.PER_CLASS)
public class SsoAdmTest extends WrenAMTestBase {

    @Test
    public void testListServers() throws Exception {
        ExecResult result = WrenAMCommands.ssoadm(
                wrenam1,
                "list-servers");
        assertSuccess(result, "Unable to exec list-servers command");

        Pattern pattern = Pattern.compile("http://wrenam[12].wrensecurity.test:8080/auth");
        Matcher matcher = pattern.matcher(result.getStdout());
        assertEquals(2, matcher.results().count(), "Exactly 2 AM servers expected");
    }

}
