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

import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

/**
 * Wren:AM test container.
 */
public class WrenAMContainer extends GenericContainer<WrenAMContainer> {

    /**
     * Create new container with the default Wren:AM image name.
     */
    public WrenAMContainer() {
        this(System.getProperty("wrenam.image", WrenAMDefaults.WRENAM_IMAGE_NAME));
    }

    /**
     * Create new container using the given image name.
     */
    public WrenAMContainer(String imageName) {
        super(imageName);
        withExposedPorts(8080);
        withDefaultWait(Duration.ofMinutes(3));

        // The following configuration is from https://github.com/WrenSecurity/wrenam/pull/209
        withCopyFileToContainer(
                MountableFile.forClasspathResource("/wrenam/config.sh", 0755),
                "/opt/wrenam/config.sh");
        withCopyFileToContainer(
                MountableFile.forClasspathResource("/wrenam/entrypoint.sh", 0755),
                "/opt/wrenam/entrypoint.sh");
        withCopyFileToContainer(
                MountableFile.forClasspathResource("/wrenam/ssoadm.sh", 0755),
                "/usr/local/bin/ssoadm");
        withCreateContainerCmdModifier(cmd -> cmd.withEntrypoint("/opt/wrenam/entrypoint.sh"));
        withCommand("catalina.sh", "run");
    }

    /**
     * Use the default startup with the given timeout.
     */
    public WrenAMContainer withDefaultWait(Duration startupTimeout) {
        return waitingFor(Wait.forHttp(WrenAMDefaults.DEPLOYMENT_URI + "/isAlive.jsp")
                .forPort(8080)
                .forStatusCode(200)
                .forResponsePredicate(body -> body.contains("Server is ALIVE"))
                .withStartupTimeout(startupTimeout));
    }

    /**
     * Use the given initial configuration properties resource.
     */
    public WrenAMContainer withInitConfig(String initResource) {
        return withCopyFileToContainer(
                MountableFile.forClasspathResource(initResource),
                "/srv/wrenam-init/init.properties");
    }

    /**
     * Use the given platform batch configuration resources.
     */
    public WrenAMContainer withConfigFiles(String mainResource, String... otherResources) {
        withCopyFileToContainer(
                MountableFile.forClasspathResource(mainResource),
                "/srv/wrenam-init/config.batch");
        for (String otherResource : otherResources) {
            withCopyFileToContainer(
                    MountableFile.forClasspathResource(otherResource),
                    "/srv/wrenam-init/" + Path.of(otherResource).getFileName());
        }
        return this;
    }

    /**
     * Get Wren:AM client for communicating directly with this server.
     */
    public WrenAMClient getWrenAMClient() {
        return new WrenAMClient(
                this,
                URI.create(getEnvMap().get("WRENAM_SERVER_URL") + WrenAMDefaults.DEPLOYMENT_URI));
    }

}
