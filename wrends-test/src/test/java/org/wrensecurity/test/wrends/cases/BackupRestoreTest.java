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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.wrensecurity.test.base.wrends.WrenDSDefaults.BASE_DN;
import static org.wrensecurity.test.base.wrends.WrenDSDefaults.ROOT_USER_DN;
import static org.wrensecurity.test.base.wrends.WrenDSDefaults.ROOT_USER_PASSWORD;
import static org.wrensecurity.test.wrends.base.WrenDSCommands.assertSuccess;

import java.util.List;
import org.forgerock.opendj.ldap.SearchScope;
import org.forgerock.opendj.ldap.responses.Result;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.wrensecurity.test.base.wrends.WrenDSContainer;

@Testcontainers
public class BackupRestoreTest {

    @Container
    @SuppressWarnings("resource")
    private static WrenDSContainer wrends = new WrenDSContainer().withSampleData();

    @Test
    public void testBackupAndRestore() throws Exception {
        // Backup all backends
        ExecResult backupResult = wrends.execInContainer(
                "bin/backup",
                "--port", "4444",
                "--bindDN", ROOT_USER_DN,
                "--bindPassword", ROOT_USER_PASSWORD,
                "--backUpAll",
                "--backupDirectory", "/opt/wrends/bak");
        assertSuccess(backupResult, "Backup operation failed");

        // Delete an entry
        try (var connection = wrends.getLdapConnection(ROOT_USER_DN, ROOT_USER_PASSWORD)) {
            Result result = connection.unwrap().delete("uid=user.0,ou=People," + BASE_DN);
            assertTrue(result.isSuccess(), "Delete unsuccessful");
        }

        // Verify entry is gone
        try (var connection = wrends.getLdapConnection()) {
            List<?> entries = connection.search(BASE_DN, SearchScope.SUBORDINATES, "(uid=user.0)", "uid");
            assertTrue(entries.isEmpty());
        }

        // Restore from backup
        ExecResult restoreResult = wrends.execInContainer(
                "bin/restore",
                "--port", "4444",
                "--bindDN", ROOT_USER_DN,
                "--bindPassword", ROOT_USER_PASSWORD,
                "--backupDirectory", "/opt/wrends/bak/userRoot");
        assertSuccess(restoreResult, "Restore operation failed");

        // Verify entry is back
        try (var connection = wrends.getLdapConnection()) {
            List<?> entries = connection.search(BASE_DN, SearchScope.SUBORDINATES, "(uid=user.0)", "uid");
            assertEquals(1, entries.size(), "Entry should be restored after backup restore");
        }
    }

}
