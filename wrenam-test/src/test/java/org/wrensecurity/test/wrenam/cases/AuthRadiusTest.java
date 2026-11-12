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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.wrensecurity.test.base.support.CustomAssertions.assertSuccess;

import java.time.Duration;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.testcontainers.containers.Container.ExecResult;
import org.wrensecurity.test.wrenam.base.WrenAMClient.AuthenticationHandler;
import org.wrensecurity.test.wrenam.base.WrenAMCommands;
import org.wrensecurity.test.wrenam.base.WrenAMContainer;
import org.wrensecurity.test.wrenam.base.WrenAMTestBase;

/**
 * RADIUS authentication test with Wren:AM acting as both RADIUS client and RADIUS server.
 *
 * <p>The RADIUS authentication module on <code>wrenam1</code> / <code>wrenam2</code> sends Access-Requests
 * to the RADIUS server running on the <code>remote</code> Wren:AM. The RADIUS server identifies clients by
 * their IP address and each client is mapped to a different authentication chain in the remote realm:
 *
 * <ul>
 * <li><code>wrenam1</code> - single step chain resulting in Access-Accept / Access-Reject</li>
 * <li><code>wrenam2</code> - two step chain where the second step is requested via Access-Challenge</li>
 * </ul>
 *
 * <p>Both sides require the Message-Authenticator attribute, so a successful authentication proves that
 * requests and responses are signed correctly.
 */
@TestInstance(Lifecycle.PER_CLASS)
public class AuthRadiusTest extends WrenAMTestBase {

    private static final String TEST_REALM = "/auth-radius";

    /**
     * Password of the test user in the remote realm (different from the local user store password).
     */
    private static final String RADIUS_PASSWORD = "radius-password";

    private static final String RADIUS_SECRET = "radius-secret";

    /**
     * RADIUS authentication port as present in <code>/proc/net/udp</code> (1812).
     */
    private static final String RADIUS_PORT_HEX = ":0714 ";

    @BeforeAll
    public void setupTestCase() throws Exception {
        remote.start();
        copySetupData(remote, "auth-radius");
        execBatchConfig(remote, "auth-radius/remote/config.batch");

        registerRadiusClient("wrenam1", wrenam1, "radiusBackend");
        registerRadiusClient("wrenam2", wrenam2, "radiusChallenge");

        // Authentication attempts before the RADIUS server is listening would end up with a timeout
        // and would mark the server as offline in the RADIUS authentication module
        await("RADIUS server listening")
                .atMost(Duration.ofSeconds(30))
                .pollInterval(Duration.ofSeconds(1))
                .until(AuthRadiusTest::isRadiusServerListening);

        setupTestConfig("auth-radius");
    }

    /**
     * Register the given Wren:AM server as a RADIUS client of the remote RADIUS server.
     */
    private static void registerRadiusClient(String name, WrenAMContainer client, String chain) throws Exception {
        String ipAddress = client.getContainerInfo().getNetworkSettings().getNetworks()
                .values().iterator().next().getIpAddress();
        ExecResult result = WrenAMCommands.ssoadm(remote, "create-sub-cfg",
                "--servicename", "RadiusServerService",
                "--subconfigname", "radiusClient",
                "--subconfigid", name,
                "--attributevalues",
                "clientIpAddress=/" + ipAddress,
                "clientSecret=" + RADIUS_SECRET,
                "clientPacketsLogged=NO",
                "clientRequireMessageAuthenticator=YES",
                "handlerClass=org.forgerock.openam.radius.server.spi.handlers.OpenAMAuthHandler",
                "handlerConfig=realm=" + TEST_REALM,
                "handlerConfig=chain=" + chain);
        assertSuccess(result, "Failed to register RADIUS client");
    }

    private static boolean isRadiusServerListening() throws Exception {
        ExecResult result = remote.execInContainer("cat", "/proc/net/udp", "/proc/net/udp6");
        return result.getStdout().contains(RADIUS_PORT_HEX);
    }

    @Test
    public void testSuccessfulAuthentication() throws Exception {
        AuthenticationHandler authHandler = wrenam1.getWrenAMClient().authenticate(TEST_REALM)
                .initializeAuth()
                .continueAuth((stage, callbacks) -> {
                    assertEquals("RADIUS1", stage);
                    callbacks.at("/0/input/0").asObject().put("value", TEST_USERNAME);
                    callbacks.at("/1/input/0").asObject().put("value", RADIUS_PASSWORD);
                });

        assertTrue(authHandler.isSucceeded(), "Successful authentication expected");
        assertEquals(TEST_REALM, authHandler.getResultState().get("realm").stringValue());
    }

    @Test
    public void testFailedAuthentication() throws Exception {
        AuthenticationHandler authHandler = wrenam1.getWrenAMClient().authenticate(TEST_REALM)
                .initializeAuth()
                .continueAuth((stage, callbacks) -> {
                    assertEquals("RADIUS1", stage);
                    callbacks.at("/0/input/0").asObject().put("value", TEST_USERNAME);
                    // Valid password in the local user store, but not on the RADIUS server
                    callbacks.at("/1/input/0").asObject().put("value", TEST_PASSWORD);
                });

        assertTrue(authHandler.isFailed(), "Failed authentication expected");
    }

    @Test
    public void testChallengeAuthentication() throws Exception {
        AuthenticationHandler authHandler = wrenam2.getWrenAMClient().authenticate(TEST_REALM)
                .initializeAuth()
                .continueAuth((stage, callbacks) -> {
                    assertEquals("RADIUS1", stage);
                    callbacks.at("/0/input/0").asObject().put("value", TEST_USERNAME);
                    callbacks.at("/1/input/0").asObject().put("value", RADIUS_PASSWORD);
                })
                // Second module callbacks are requested one by one with Reply-Message as a prompt
                .continueAuth((stage, callbacks) -> {
                    assertEquals("RADIUS2", stage);
                    assertTrue(callbacks.at("/0/output/0/value").asString().endsWith("User Name:]: "),
                            "Unexpected challenge prompt: " + callbacks);
                    callbacks.at("/0/input/0").asObject().put("value", TEST_USERNAME);
                })
                .continueAuth((stage, callbacks) -> {
                    assertEquals("RADIUS2", stage);
                    assertTrue(callbacks.at("/0/output/0/value").asString().endsWith("Password:]: "),
                            "Unexpected challenge prompt: " + callbacks);
                    callbacks.at("/0/input/0").asObject().put("value", RADIUS_PASSWORD);
                });

        assertTrue(authHandler.isSucceeded(), "Successful authentication expected");
    }

}
