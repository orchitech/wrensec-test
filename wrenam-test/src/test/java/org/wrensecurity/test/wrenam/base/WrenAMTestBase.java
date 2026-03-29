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

package org.wrensecurity.test.wrenam.base;

import static org.wrensecurity.test.base.support.CustomAssertions.assertSuccess;

import java.net.URI;
import org.junit.jupiter.api.BeforeAll;
import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.containers.ContainerState;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.lifecycle.Startables;
import org.testcontainers.utility.MountableFile;
import org.wrensecurity.test.base.wrends.WrenDSContainer;
import tools.jackson.databind.ObjectMapper;

/**
 * Shared superclass for Wren:AM system tests with common deployment infrastructure.
 *
 * <p>We might want to make this pluggable in the feature so that we can run the same tests
 * with different deployment setup (single server, multiple user stores, ...).
 *
 * <p>Currently the platform is started automatically in {@link #setupEnvironment()} lifecycle
 * hook and stopped only when the JVM shuts down. Future improvement might be to introduce
 * environment bootstrap/shutdown by switching to <i>JUnit Platform Suite Engine</i>.
 */
public abstract class WrenAMTestBase {

    protected static final String TEST_USERNAME = "john";

    protected static final String TEST_PASSWORD = "password";

    protected static final Network network = Network.newNetwork();

    @SuppressWarnings({ "rawtypes", "resource" })
    protected static final GenericContainer ingress = new GenericContainer(WrenAMDefaults.HAPROXY_IMAGE_NAME)
            .withNetwork(network)
            .withNetworkAliases("wrenam.wrensecurity.test")
            .withExposedPorts(8080)
            .withCopyFileToContainer(
                    MountableFile.forClasspathResource("/haproxy/haproxy.cfg"),
                    "/usr/local/etc/haproxy/haproxy.cfg")
            .waitingFor(Wait.forHttp("/monitor").forPort(8080));

    @SuppressWarnings("resource")
    protected static final WrenDSContainer config1 = new WrenDSContainer()
            .withNetwork(network)
            .withNetworkAliases("config1.wrensecurity.test")
            .withEnv("BASE_DN", WrenAMDefaults.CONFIG_STORE_BASE_DN);

    @SuppressWarnings("resource")
    protected static final WrenDSContainer users1 = new WrenDSContainer()
            .withNetwork(network)
            .withNetworkAliases("users1.wrensecurity.test")
            .withEnv("BASE_DN", WrenAMDefaults.USER_STORE_BASE_DN)
            .withInitResources(
                    "/userstore/init/05-config.sh",
                    "/userstore/init/10-data.ldif");

    @SuppressWarnings("resource")
    protected static final WrenAMContainer wrenam1 = new WrenAMContainer()
            .dependsOn(config1)
            .dependsOn(users1)
            .dependsOn(ingress)
            .withNetwork(network)
            .withNetworkAliases("wrenam1.wrensecurity.test")
            .withEnv("WRENAM_SERVER_URL", "http://wrenam1.wrensecurity.test:8080")
            .withInitConfig("/wrenam/init/init-wrenam1.properties");

    @SuppressWarnings("resource")
    protected static final WrenAMContainer wrenam2 = new WrenAMContainer()
            .dependsOn(config1)
            .dependsOn(users1)
            .dependsOn(ingress)
            .dependsOn(wrenam1)
            .withNetwork(network)
            .withNetworkAliases("wrenam2.wrensecurity.test")
            .withEnv("WRENAM_SERVER_URL", "http://wrenam2.wrensecurity.test:8080")
            .withInitConfig("/wrenam/init/init-wrenam2.properties");

    @SuppressWarnings("resource")
    protected static final WrenAMContainer remote = new WrenAMContainer()
            .withNetwork(network)
            .withNetworkAliases("wrenam.wrensecurity.remote")
            .withEnv("WRENAM_SERVER_URL", "http://wrenam.wrensecurity.remote:8080")
            .withInitConfig("/wrenam/init/init-remote.properties");

    protected final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeAll
    public static void setupTestBase() throws Exception {
        Startables.deepStart(wrenam1, wrenam2).get();
    }

    /**
     * Copy setup data to the specified container.
     */
    protected static void copySetupData(ContainerState container, String path) {
        container.copyFileToContainer(MountableFile.forClasspathResource(
                "/cases/" + path),
                "/srv/wrenam/setup/" + path);
    }

    /**
     * Execute batch configuration located on the given path.
     */
    protected static void execBatchConfig(ContainerState container, String path) throws Exception {
        ExecResult result = WrenAMCommands.ssoadm(container, "do-batch",
                "--batchfile", "setup/" + path);
        assertSuccess(result, "Failed to configure AM");
    }

    /**
     * Configure Wren:AM for the test case with the given name.
     */
    protected static void setupTestConfig(String name) throws Exception {
        copySetupData(wrenam1, name);
        copySetupData(wrenam2, name);
        execBatchConfig(wrenam1, name + "/config.batch");
    }

    /**
     * Import contents of a PKCS12 keystore on the given path to the default Wren:AM keystore.
     */
    protected static void importKeystore(ContainerState container, String path) throws Exception {
        ExecResult result = container.execInContainer(
                "keytool", "-importkeystore",
                "-srckeystore", path,
                "-srcstoretype", "PKCS12",
                "-srcstorepass", "changeit",
                "-destkeystore", "/srv/wrenam/auth/keystore.jceks",
                "-deststoretype", "JCEKS",
                "-deststorepass:file", "/srv/wrenam/auth/.storepass");
        assertSuccess(result, "Unable to import keystore");
    }

    /**
     * Get Wren:AM client.
     */
    protected static WrenAMClient getWrenAMClient() {
        return new WrenAMClient(
                ingress,
                URI.create("http://wrenam.wrensecurity.test:8080/auth"));
    }

}
