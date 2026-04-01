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

import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.wrensecurity.test.base.support.CustomAssertions.assertSuccess;
import static org.wrensecurity.test.base.wrends.WrenDSDefaults.BASE_DN;
import static org.wrensecurity.test.base.wrends.WrenDSDefaults.ROOT_USER_DN;
import static org.wrensecurity.test.base.wrends.WrenDSDefaults.ROOT_USER_PASSWORD;

import com.github.dockerjava.api.command.ExecCreateCmdResponse;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.List;
import org.forgerock.opendj.ldap.SearchScope;
import org.forgerock.opendj.ldap.responses.Result;
import org.junit.jupiter.api.Test;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.wrensecurity.test.base.wrends.WrenDSCommands;
import org.wrensecurity.test.base.wrends.WrenDSContainer;
import org.wrensecurity.test.wrends.base.StringBufferResultCallback;

@Testcontainers
public class LdapToolsTest {

    @Container
    @SuppressWarnings("resource")
    private static WrenDSContainer wrends = new WrenDSContainer().withSampleData();

    @Test
    public void testLdapDelete() throws Exception {
        // Verify entry exists
        try (var connection = wrends.getLdapConnection()) {
            List<?> entries = connection.search(BASE_DN, SearchScope.SUBORDINATES, "(uid=user.0)");
            assertEquals(1, entries.size(), "Entry should exist before delete");
        }

        // Delete entry
        ExecResult deleteResult = WrenDSCommands.ldapDelete(wrends, "uid=user.0,ou=People," + BASE_DN);
        assertSuccess(deleteResult, "Failed to delete entry");

        // Verify entry is gone
        try (var connection = wrends.getLdapConnection()) {
            List<?> result = connection.search(BASE_DN, SearchScope.SUBORDINATES, "(uid=user.0)", "uid");
            assertEquals(0, result.size(), "Entry should not exist after delete");
        }
    }

    @Test
    public void testPersistentSearch() throws Exception {
        var dockerClient = DockerClientFactory.instance().client();

        ExecCreateCmdResponse searchCommand = dockerClient.execCreateCmd(wrends.getContainerId())
                .withAttachStdout(true).withAttachStderr(true)
                .withCmd("ldapsearch",
                        "--port", "1389",
                        "--bindDN", ROOT_USER_DN,
                        "--bindPassword", ROOT_USER_PASSWORD,
                        "--baseDN", BASE_DN,
                        "--persistentSearch", "ps:any:true:true",
                        "(objectClass=*)")
                .exec();

        PipedOutputStream pipeOut = new PipedOutputStream();
        PipedInputStream pipeIn = new PipedInputStream(pipeOut);

        StringBufferResultCallback searchResult = dockerClient.execStartCmd(searchCommand.getId())
                .withStdIn(pipeIn)
                .withTty(true)
                .exec(new StringBufferResultCallback());

        // Allow persistent search to start
        Thread.sleep(1000);

        // Perform LDAP modification
        try (var connection = wrends.getLdapConnection(ROOT_USER_DN, ROOT_USER_PASSWORD)) {
            Result result = connection.unwrap().modify(
                    "dn: dc=example,dc=com",
                    "changetype: modify",
                    "replace: description",
                    "description: bar");
            assertTrue(result.isSuccess(), "Modify request failed");
        }

        // Verify modification was captured by the persistent search
        await("Wait for modification capture").untilAsserted(() -> {
            assertEquals(
                """
                # Persistent search change type:  modify
                dn: dc=example,dc=com
                objectClass: top
                objectClass: domain
                dc: example
                description: bar
                """.trim(),
                searchResult.toString().trim(), "Modification not captured");
        });

        // Send SIGINT to abort the search
        pipeOut.write(3);
        pipeOut.flush();
        pipeOut.close();
    }

}
