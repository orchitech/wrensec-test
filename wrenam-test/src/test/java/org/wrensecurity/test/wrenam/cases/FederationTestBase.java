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

import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.BeforeAll;
import org.wrensecurity.test.wrenam.base.WrenAMTestBase;

/**
 * Shared superclass for federation system tests.
 */
public class FederationTestBase extends WrenAMTestBase {

    protected static final String TEST_REALM = "/federation";

    protected static final String LOCAL_IDP_META_ALIAS = "/federation/local-idp";

    protected static final String LOCAL_SP_META_ALIAS = "/federation/local-sp";

    protected static final String REMOTE_IDP_ENTITY_ID = "https://wrenam.wrensecurity.remote/auth/saml/test-idp";

    protected static final String REMOTE_SP_ENTITY_ID = "https://wrenam.wrensecurity.remote/auth/saml/test-sp";

    private static final AtomicBoolean SETUP_GUARD = new AtomicBoolean();

    @BeforeAll
    public static void setupTestFederation() throws Exception {
        if (SETUP_GUARD.getAndSet(true)) {
            return;
        }

        // Setup local configuration
        copySetupData(wrenam1, "federation");
        importKeystore(wrenam1, "/srv/wrenam/setup/federation/keystore.p12");
        copySetupData(wrenam2, "federation");
        importKeystore(wrenam2, "/srv/wrenam/setup/federation/keystore.p12");
        execBatchConfig(wrenam1, "federation/local/config.batch");

        // Setup remote configuration
        remote.start();
        copySetupData(remote, "federation");
        importKeystore(remote, "/srv/wrenam/setup/federation/keystore.p12");
        execBatchConfig(remote, "federation/remote/config.batch");
    }

}
