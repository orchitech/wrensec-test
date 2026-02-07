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
import static org.wrensecurity.test.wrends.base.WrenDSCommands.assertSuccess;
import static org.wrensecurity.test.wrends.base.WrenDSCommands.dsconfig;
import static org.wrensecurity.test.wrends.base.WrenDSConstants.BASE_DN;
import static org.wrensecurity.test.wrends.base.WrenDSConstants.ROOT_USER_DN;
import static org.wrensecurity.test.wrends.base.WrenDSConstants.ROOT_USER_PASSWORD;

import java.io.IOException;
import java.util.List;
import org.forgerock.opendj.ldap.SearchScope;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.wrensecurity.test.wrends.base.WrenDSContainer;

@Testcontainers
public class AccessControlTest {

    @Container
    @SuppressWarnings("resource")
    private static WrenDSContainer wrends = new WrenDSContainer().withSampleData();

    @Test
    public void testDisableAnonymous() throws Exception {
        // 1. Test anonymous search - should work initially
        try (var connection = wrends.getLdapConnection()) {
            List<?> entries = connection.search(BASE_DN, SearchScope.WHOLE_SUBTREE, "(uid=user.1)", "sn");
            assertEquals(1, entries.size(), "Anonymous search should return 1 result initially");
        }

        // 2. Remove anonymous access using dsconfig
        removeAnonymousAccess();

        // 3. Test anonymous search again - should fail now
        try (var connection = wrends.getLdapConnection()) {
            List<?> entries = connection.search(BASE_DN, SearchScope.WHOLE_SUBTREE, "(uid=user.1)", "sn");
            assertTrue(entries.isEmpty(), "Anonymous search should return no results after disabling");
        }

        // 4. Test authenticated search - should still work
        try (var connection = wrends.getLdapConnection(ROOT_USER_DN, ROOT_USER_PASSWORD)) {
            List<?> entries = connection.search(BASE_DN, SearchScope.WHOLE_SUBTREE, "(uid=user.1)", "sn");
            assertEquals(1, entries.size(), "Authenticated search should return 1 result");
        }
    }

    private void removeAnonymousAccess() throws IOException, InterruptedException {
        String aciToRemove = "(targetattr!=\"userPassword||authPassword||debugsearchindex||changes||changeNumber||" +
                "changeType||changeTime||targetDN||newRDN||newSuperior||deleteOldRDN\")" +
                "(version 3.0; acl \"Anonymous read access\"; allow (read,search,compare) userdn=\"ldap:///anyone\";)";

        ExecResult result = dsconfig(wrends,
                "set-access-control-handler-prop",
                "--remove", "global-aci:" + aciToRemove);
        assertSuccess(result, "Failed to remove anonymous access");
    }

}
