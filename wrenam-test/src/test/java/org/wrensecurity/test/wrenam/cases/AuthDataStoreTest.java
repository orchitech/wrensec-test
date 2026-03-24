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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.wrensecurity.test.wrenam.base.WrenAMClient;
import org.wrensecurity.test.wrenam.base.WrenAMClient.AuthenticationHandler;
import org.wrensecurity.test.wrenam.base.WrenAMDefaults;
import org.wrensecurity.test.wrenam.base.WrenAMTestBase;

@TestInstance(Lifecycle.PER_CLASS)
public class AuthDataStoreTest extends WrenAMTestBase {

    @Test
    public void testSuccessfulAuthentication() throws Exception {
        WrenAMClient wrenamClient = getWrenAMClient();

        AuthenticationHandler authHandler = wrenamClient.authenticate()
            .initializeAuth()
            .continueAuth((stage, callbacks) -> {
                assertEquals("DataStore1", stage);
                callbacks.at("/0/input/0").asObject().put("value", WrenAMDefaults.ADMIN_USERNAME);
                callbacks.at("/1/input/0").asObject().put("value", WrenAMDefaults.ADMIN_PASSWORD);

            });

        assertTrue(authHandler.isSucceeded(), "Successful authentication expected");
        assertEquals("/", authHandler.getResultState().get("realm").stringValue());
    }

    @Test
    public void testFailedAuthentication() throws Exception {
        WrenAMClient wrenamClient = getWrenAMClient();

        AuthenticationHandler authHandler = wrenamClient.authenticate()
            .initializeAuth()
            .continueAuth((stage, callbacks) -> {
                assertEquals("DataStore1", stage);
                callbacks.at("/0/input/0").asObject().put("value", WrenAMDefaults.ADMIN_USERNAME);
                callbacks.at("/1/input/0").asObject().put("value", "wrong_password");

            });

        assertTrue(authHandler.isFailed(), "Failed authentication expected");
    }

}
