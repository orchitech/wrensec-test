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

package org.wrensecurity.test.base.wrends;

import java.nio.file.Path;
import java.time.Duration;
import org.forgerock.opendj.ldap.Connection;
import org.forgerock.opendj.ldap.LDAPConnectionFactory;
import org.forgerock.opendj.ldap.LdapException;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.containers.wait.strategy.WaitAllStrategy;
import org.testcontainers.utility.MountableFile;

/**
 * Wren:DS test container.
 */
public class WrenDSContainer extends GenericContainer<WrenDSContainer> {

    private LDAPConnectionFactory connectionFactory;

    /**
     * Create new container with the default Wren:DS image name.
     */
    public WrenDSContainer() {
        this(System.getProperty("wrends.image", WrenDSDefaults.WRENDS_IMAGE_NAME));
    }

    /**
     * Create new container with the given image name.
     */
    public WrenDSContainer(String imageName) {
        super(imageName);
        withExposedPorts(1389, 1636, 4444);
        withDefaultWait(Duration.ofMinutes(1));
    }

    /**
     * Use the default startup with the given timeout.
     */
    public WrenDSContainer withDefaultWait(Duration startupTimeout) {
        return waitingFor(new WaitAllStrategy()
                .withStrategy(Wait.forLogMessage(
                        ".*Started listening for new connections on LDAP Connection Handler.*",
                        2 /* one for init and one for the actual startup */))
                .withStartupTimeout(startupTimeout));
    }

    /**
     * Initialize Wren:DS with the sample data of size 200.
     */
    public WrenDSContainer withSampleData() {
        return withSampleData(200);
    }

    /**
     * Initialize Wren:DS with the sample of the given size.
     */
    public WrenDSContainer withSampleData(int size) {
        return withEnv("ADDITIONAL_SETUP_ARGS", "--sampleData " + size);
    }

    /**
     * Use the given init resources (config scripts or LDIF files).
     */
    public WrenDSContainer withInitResources(String... resources) {
        for (String resource : resources) {
            int mode = resource.endsWith(".sh") ? 0775 : 0664;
            withCopyFileToContainer(
                    MountableFile.forClasspathResource(resource, mode),
                    "/opt/wrends/bootstrap/init/" + Path.of(resource).getFileName());
        }
        return this;
    }

    /**
     * Get server LDAP port.
     */
    public int getLdapPort() {
        return getMappedPort(1389);
    }

    /**
     * Get server <i>admin</i> port.
     */
    public int getAdminPort() {
        return getMappedPort(4444);
    }

    /**
     * Get LDAP connection factory.
     */
    public synchronized LDAPConnectionFactory getLdapConnectionFactory() {
        if (connectionFactory == null) {
            connectionFactory = new LDAPConnectionFactory(getHost(), getLdapPort());
        }
        return connectionFactory;
    }

    /**
     * Get fully established anonymous LDAP connection.
     */
    public WrenDSConnection getLdapConnection() throws LdapException {
        return new WrenDSConnection(getLdapConnectionFactory().getConnection());
    }

    /**
     * Get fully established LDAP connection authenticated with a simple bind.
     */
    public WrenDSConnection getLdapConnection(String name, String password) throws LdapException {
        Connection connection = getLdapConnectionFactory().getConnection();
        connection.bind(name, password.toCharArray());
        return new WrenDSConnection(connection);
    }

    /**
     * Get fully established root user LDAP connection.
     */
    public WrenDSConnection getRootLdapConnection() throws LdapException {
        return getLdapConnection(WrenDSDefaults.ROOT_USER_DN, WrenDSDefaults.ROOT_USER_PASSWORD);
    }

    @Override
    public synchronized void stop() {
        if (connectionFactory != null) {
            connectionFactory.close();
            connectionFactory = null;
        }
        super.stop();
    }

}
