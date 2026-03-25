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
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.forgerock.opendj.ldap.SearchScope;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.wrensecurity.test.base.wrends.WrenDSContainer;

@Testcontainers
public class AccessAuditTest {

    @Container
    @SuppressWarnings("resource")
    private static WrenDSContainer wrends = new WrenDSContainer();

    @Test
    public void testAccessLog() throws Exception {
        try (var connection = wrends.getLdapConnection()) {
            connection.search("", SearchScope.BASE_OBJECT, "(cn=audit-test)");
        }

        await("Match search request").untilAsserted(() -> {
            ExecResult result = wrends.execInContainer("cat", "instance/logs/ldap-access.audit.json");
            assertTrue(result.getStdout().contains("(cn=audit-test)"));
        });
    }

}
