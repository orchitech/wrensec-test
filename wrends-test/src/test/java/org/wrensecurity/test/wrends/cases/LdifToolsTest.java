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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.wrensecurity.test.wrends.base.WrenDSCommands.assertSuccess;
import static org.wrensecurity.test.wrends.base.WrenDSConstants.BASE_DN;
import static org.wrensecurity.test.wrends.base.WrenDSConstants.ROOT_USER_DN;
import static org.wrensecurity.test.wrends.base.WrenDSConstants.ROOT_USER_PASSWORD;

import java.util.List;
import org.forgerock.opendj.ldap.SearchScope;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;
import org.wrensecurity.test.wrends.base.WrenDSContainer;

@Testcontainers
public class LdifToolsTest {

    @Container
    @SuppressWarnings("resource")
    private static WrenDSContainer wrends = new WrenDSContainer();

    @Test
    public void testImportLdif() throws Exception {
        wrends.copyFileToContainer(
                MountableFile.forClasspathResource("/ldif/example.template"),
                "/tmp/example.template");

        // Generate LDIF from template
        ExecResult makeldifResult = wrends.execInContainer(
                "makeldif",
                "--outputLdif", "/tmp/generated.ldif",
                "/tmp/example.template");
        assertSuccess(makeldifResult, "Failed to generate LDIF from template");

        // Import generated LDIF
        ExecResult importResult = wrends.execInContainer(
                "import-ldif",
                "--hostname", "localhost",
                "--port", "4444",
                "--trustAll",
                "--bindDN", ROOT_USER_DN,
                "--bindPassword", ROOT_USER_PASSWORD,
                "--includeBranch", BASE_DN,
                "--ldifFile", "/tmp/generated.ldif");
        assertSuccess(importResult, "Failed to import LDIF");

        // Verify imported data is searchable
        try (var connection = wrends.getLdapConnection()) {
            List<?> entries = connection.search("ou=People," + BASE_DN, SearchScope.SINGLE_LEVEL,
                    "(objectClass=organizationalUnit)");
            assertEquals(10, entries.size(), "Should find 10 organizational units from imported template");
        }
    }

}
