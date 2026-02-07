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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.wrensecurity.test.wrends.base.WrenDSCommands.assertSuccess;
import static org.wrensecurity.test.wrends.base.WrenDSConstants.BASE_DN;
import static org.wrensecurity.test.wrends.base.WrenDSConstants.ROOT_USER_DN;
import static org.wrensecurity.test.wrends.base.WrenDSConstants.ROOT_USER_PASSWORD;

import java.util.List;
import org.forgerock.opendj.ldap.SearchScope;
import org.forgerock.opendj.ldap.responses.Result;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.containers.Network;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.wrensecurity.test.wrends.base.WrenDSContainer;

@Testcontainers
public class ReplicationTest {

    private static final Network network = Network.newNetwork();

    @Container
    @SuppressWarnings("resource")
    private static WrenDSContainer master = new WrenDSContainer().withSampleData(10)
            .withNetwork(network)
            .withNetworkAliases("wrends-test1");

    @Container
    @SuppressWarnings("resource")
    private static WrenDSContainer replica = new WrenDSContainer()
            .withNetwork(network)
            .withNetworkAliases("wrends-test2");

    @Test
    public void testReplication() throws Exception {
        // Verify replica does not have sample data
        try (var connection = replica.getLdapConnection()) {
            List<?> entries = connection.search(BASE_DN, SearchScope.WHOLE_SUBTREE, "(uid=user.0)", "uid");
            assertTrue(entries.isEmpty(), "Replica should not have sample data initially");
        }

        // Enable replication
        ExecResult enableResult = master.execInContainer(
                "dsreplication", "enable",
                "--adminUID", "admin",
                "--adminPassword", ROOT_USER_PASSWORD,
                "--trustAll",
                "--no-prompt",
                "--baseDN", BASE_DN,
                "--host1", "wrends-test1",
                "--port1", "4444",
                "--bindDN1", ROOT_USER_DN,
                "--bindPassword1", ROOT_USER_PASSWORD,
                "--replicationPort1", "8989",
                "--host2", "wrends-test2",
                "--port2", "4444",
                "--bindDN2", ROOT_USER_DN,
                "--bindPassword2", ROOT_USER_PASSWORD,
                "--replicationPort2", "8989");
        assertSuccess(enableResult, "Failed to enable replication");

        // Initialize replication
        ExecResult initResult = master.execInContainer(
                "dsreplication", "initialize-all",
                "--adminUID", "admin",
                "--adminPassword", ROOT_USER_PASSWORD,
                "--trustAll",
                "--no-prompt",
                "--baseDN", BASE_DN,
                "--hostname", "wrends-test1",
                "--port", "4444");
        assertSuccess(initResult, "Failed to initialize replication");

        // Verify sample data replicated to replica
        try (var connection = replica.getLdapConnection()) {
            List<?> entries = connection.search(BASE_DN, SearchScope.WHOLE_SUBTREE, "(uid=user.0)", "uid");
            assertFalse(entries.isEmpty(), "Replica should have sample data after initialization");
        }

        // Delete entry on replica
        try (var connection = replica.getLdapConnection(ROOT_USER_DN, ROOT_USER_PASSWORD)) {
            Result result = connection.unwrap().delete("uid=user.0,ou=People," + BASE_DN);
            assertTrue(result.isSuccess(), "Failed to delete entry on replica");
        }

        // Verify deletion replicated to master
        try (var connection = master.getLdapConnection()) {
            await("Wait for replication to propagate").untilAsserted(() -> {
                List<?> entries = connection.search(BASE_DN, SearchScope.WHOLE_SUBTREE, "(uid=user.0)", "uid");
                assertTrue(entries.isEmpty(), "Deleted entry should be replicated to master");
            });
        }
    }

}
