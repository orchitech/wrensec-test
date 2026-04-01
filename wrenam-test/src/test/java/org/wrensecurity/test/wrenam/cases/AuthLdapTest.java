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
import static org.wrensecurity.test.wrenam.base.WrenAMDefaults.USER_STORE_BASE_DN;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.wrensecurity.test.wrenam.base.WrenAMClient;
import org.wrensecurity.test.wrenam.base.WrenAMClient.AuthenticationHandler;
import org.wrensecurity.test.wrenam.base.WrenAMTestBase;

@TestInstance(Lifecycle.PER_CLASS)
public class AuthLdapTest extends WrenAMTestBase {

    private static final String TEST_REALM = "/auth-ldap";

    private static final String TEST_USER_DN = "uid=case-auth-ldap,ou=people," + USER_STORE_BASE_DN;

    private static final String TEST_USER_CN = "Test Auth LDAP";

    private static final String TEST_USER_PASSWORD = "password";

    private static final String NEW_VALID_PASSWORD = "Password1";

    @BeforeAll
    public void setupTestCase() throws Exception {
        setupTestConfig("auth-ldap");

        try (var connection = users1.getRootLdapConnection()) {
            connection.unwrap().add(
                    "dn: " + TEST_USER_DN,
                    "changetype: add",
                    "objectClass: inetOrgPerson",
                    "uid: case-auth-ldap",
                    "cn: " + TEST_USER_CN,
                    "sn: Doe",
                    "userPassword: password");
        }
    }

    @Test
    public void testSuccessfulAuthentication() throws Exception {
        WrenAMClient wrenamClient = getWrenAMClient();

        AuthenticationHandler authHandler = wrenamClient.authenticate(TEST_REALM)
            .initializeAuth()
            .continueAuth((stage, callbacks) -> {
                assertEquals("LDAP1", stage);
                callbacks.at("/0/input/0").asObject().put("value", TEST_USER_CN);
                callbacks.at("/1/input/0").asObject().put("value", TEST_USER_PASSWORD);
            });

        assertTrue(authHandler.isSucceeded(), "Successful authentication expected");
        assertEquals(TEST_REALM, authHandler.getResultState().get("realm").stringValue());
    }

    @Test
    public void testFailedAuthentication() throws Exception {
        WrenAMClient wrenamClient = getWrenAMClient();

        AuthenticationHandler authHandler = wrenamClient.authenticate(TEST_REALM)
            .initializeAuth()
            .continueAuth((stage, callbacks) -> {
                assertEquals("LDAP1", stage);
                callbacks.at("/0/input/0").asObject().put("value", TEST_USER_CN);
                callbacks.at("/1/input/0").asObject().put("value", "wrong_password");
            });

        assertTrue(authHandler.isFailed(), "Failed authentication expected");
    }

    @Test
    public void testForcedPasswordChange() throws Exception {
        // Set test user's `pwdReset` attribute to force password change
        try (var connection = users1.getRootLdapConnection()) {
            connection.unwrap().modify(
                    "dn: " + TEST_USER_DN,
                    "changetype: modify",
                    "replace: pwdReset",
                    "pwdReset: TRUE");
        }

        WrenAMClient wrenamClient = getWrenAMClient();

        // The first authentication should require password change
        AuthenticationHandler firstAuthHandler = wrenamClient.authenticate(TEST_REALM)
                .initializeAuth()
                .continueAuth((stage, callbacks) -> {
                    assertEquals("LDAP1", stage);
                    callbacks.at("/0/input/0").asObject().put("value", TEST_USER_CN);
                    callbacks.at("/1/input/0").asObject().put("value", TEST_USER_PASSWORD);

                })
                .continueAuth((stage, callbacks) -> {
                    assertEquals("LDAP2", stage);
                    callbacks.at("/0/input/0").asObject().put("value", TEST_USER_PASSWORD);
                    callbacks.at("/1/input/0").asObject().put("value", NEW_VALID_PASSWORD);
                    callbacks.at("/2/input/0").asObject().put("value", NEW_VALID_PASSWORD);
                });

        assertTrue(firstAuthHandler.isSucceeded(), "Successful authentication expected");

        // Logout before the second authentication attempt
        wrenamClient.logoutToken(firstAuthHandler.getSsoTokenId()).assertSuccess();

        // The second authentication should succeed without the password change
        AuthenticationHandler secondAuthHandler = wrenamClient.authenticate(TEST_REALM)
                .initializeAuth()
                .continueAuth((stage, callbacks) -> {
                    assertEquals("LDAP1", stage);
                    callbacks.at("/0/input/0").asObject().put("value", TEST_USER_CN);
                    callbacks.at("/1/input/0").asObject().put("value", NEW_VALID_PASSWORD);

                });

        assertTrue(secondAuthHandler.isSucceeded(), "Successful authentication expected");
    }

}
