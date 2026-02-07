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

import static org.forgerock.opendj.ldap.requests.Requests.newSearchRequest;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.wrensecurity.test.wrends.base.WrenDSConstants.BASE_DN;
import static org.wrensecurity.test.wrends.base.WrenDSConstants.ROOT_USER_DN;
import static org.wrensecurity.test.wrends.base.WrenDSConstants.ROOT_USER_PASSWORD;

import java.util.List;
import org.forgerock.opendj.ldap.LdapPromise;
import org.forgerock.opendj.ldap.SearchScope;
import org.forgerock.opendj.ldap.controls.PersistentSearchChangeType;
import org.forgerock.opendj.ldap.controls.PersistentSearchRequestControl;
import org.forgerock.opendj.ldap.responses.Result;
import org.forgerock.opendj.ldif.LDIF;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.wrensecurity.test.wrends.base.CollectingSearchResultHandler;
import org.wrensecurity.test.wrends.base.WrenDSContainer;

@Testcontainers
public class LdapProtocolTest {

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
        try (var connection = wrends.getLdapConnection(ROOT_USER_DN, ROOT_USER_PASSWORD)) {
            Result result = connection.unwrap().delete("uid=user.0,ou=People," + BASE_DN);
            assertTrue(result.isSuccess(), "Delete unsuccessful");
        }

        // Verify entry is gone
        try (var connection = wrends.getLdapConnection()) {
            List<?> result = connection.search(BASE_DN, SearchScope.SUBORDINATES, "(uid=user.0)", "uid");
            assertEquals(0, result.size(), "Entry should not exist after delete");
        }
    }

    @Test
    public void testPersistentSearch() throws Exception {
        var searchHandler = new CollectingSearchResultHandler();

        try (var searchConnection = wrends.getLdapConnection(ROOT_USER_DN, ROOT_USER_PASSWORD)) {
            // Start persistent search in the background
            LdapPromise<Result> resultPromise = searchConnection.unwrap().searchAsync(
                    newSearchRequest(BASE_DN, SearchScope.BASE_OBJECT, "(objectclass=*)")
                        .addControl(PersistentSearchRequestControl
                            .newControl(true, true, false, PersistentSearchChangeType.values())),
                    searchHandler);

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

            // Wait briefly, then cancel the persistent search
            Thread.sleep(1000);
            resultPromise.cancel(true);
        }

        // Verify modification was captured by the persistent search
        assertEquals(1, searchHandler.getEntries().size());
        assertEquals(
                """
                dn: dc=example,dc=com
                objectClass: top
                objectClass: domain
                dc: example
                description: bar
                """.trim(),
                LDIF.toLDIF(searchHandler.getEntries().get(0)).trim(), "Modification not captured");
    }

}
