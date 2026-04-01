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

import static org.wrensecurity.test.wrenam.base.WrenAMDefaults.ADMIN_PASSWORD;
import static org.wrensecurity.test.wrenam.base.WrenAMDefaults.ADMIN_USERNAME;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.wrensecurity.test.wrenam.base.WrenAMClient.HttpResponseWrapper;
import org.wrensecurity.test.wrenam.base.WrenAMTestBase;

@TestInstance(Lifecycle.PER_CLASS)
public class HighAvailabilityTest extends WrenAMTestBase {

    @Test
    public void testSessionFailover() throws Exception {
        String adminToken = wrenam1.getWrenAMClient().authenticate()
                .immediateAuth(ADMIN_USERNAME, ADMIN_PASSWORD)
                .getSsoTokenId();

        // Single CTS means no replication lag (i.e. no need for Awaitility)
        HttpResponseWrapper idResponse = wrenam2.getWrenAMClient()
                .newHttpRequest("json/users?_action=idFromSession")
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .ssoHeader(adminToken)
                .postBody("{}")
                .buildAndSend();
        idResponse.assertSuccess();
    }

}
