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

import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.concurrent.Callable;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.Container.ExecResult;
import org.wrensecurity.test.base.wrends.WrenDSDefaults;
import org.wrensecurity.test.wrenam.base.WrenAMClient.AuthenticationHandler;
import org.wrensecurity.test.wrenam.base.WrenAMDefaults;
import org.wrensecurity.test.wrenam.base.WrenAMTestBase;

/**
 * Verifies that Wren:AM recovers automatically and can authenticate users after its configuration store is restarted.
 */
class ConfigStoreRestartTest extends WrenAMTestBase {

    private static final Logger LOGGER = LoggerFactory.getLogger(ConfigStoreRestartTest.class);

    /**
     * How long to wait for the config store to serve after a restart.
     */
    private static final Duration CONFIG_STORE_READY_TIMEOUT = Duration.ofMinutes(1);

    /**
     * How long a failed authentication is given to recover before it is treated as the failure this test is about.
     */
    private static final Duration RECOVERY_GRACE = Duration.ofSeconds(60);

    /**
     * Delay between individual authentication attempts.
     */
    private static final Duration POLL_INTERVAL = Duration.ofSeconds(1);

    /**
     * Number of config store restarts to perform.
     */
    private static final int RESTART_ITERATIONS = Integer.getInteger("configStoreRestart.iterations", 25);

    @Test
    @SuppressWarnings("resource")
    public void testAuthenticationAfterConfigStoreRestarts() throws Exception {
        assertTrue(authenticate().isSucceeded(), "Initial authentication was expected to succeed.");
        var dockerClient = DockerClientFactory.instance().client();

        for (int iteration = 1; iteration <= RESTART_ITERATIONS; iteration++) {
            LOGGER.info("Test iteration #{}", iteration);

            dockerClient.killContainerCmd(config1.getContainerId()).exec();
            dockerClient.startContainerCmd(config1.getContainerId()).exec();
            awaitConfigStoreAvailable();

            assertAuthenticationWithRetryAttempts();
        }
    }

    private static void assertAuthenticationWithRetryAttempts() throws Exception {
        AuthenticationHandler authHandler = authenticate();
        if (!authHandler.isSucceeded()) {
            assertAuthenticationRecovers();
        }
    }

    private static void assertAuthenticationRecovers() throws Exception {
        await("Authentication recovery")
                .logging()
                .atMost(RECOVERY_GRACE)
                .pollInterval(POLL_INTERVAL)
                .until(authenticate()::isSucceeded);
    }

    private static AuthenticationHandler authenticate() throws Exception {
        return wrenam1.getWrenAMClient()
                .authenticate()
                .immediateAuth(WrenAMDefaults.ADMIN_USERNAME, WrenAMDefaults.ADMIN_PASSWORD);
    }

    private static void awaitConfigStoreAvailable() {
        var readEntry = (Callable<ExecResult>) () -> config1.execInContainer(
                "ldapsearch",
                "--port", "1389",
                "--bindDN", WrenDSDefaults.ROOT_USER_DN,
                "--bindPassword", WrenDSDefaults.ROOT_USER_PASSWORD,
                "--baseDN", WrenAMDefaults.CONFIG_STORE_BASE_DN,
                "--searchScope", "base",
                "(objectClass=*)"
        );
        await("Config store serving ")
                .atMost(CONFIG_STORE_READY_TIMEOUT)
                .pollInterval(Duration.ofMillis(500))
                .until(() -> readEntry.call().getExitCode() == 0);
    }

}
