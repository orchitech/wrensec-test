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
package org.wrensecurity.test.wrends.base;

import java.time.Duration;
import org.forgerock.opendj.ldap.Connection;
import org.forgerock.opendj.ldap.LDAPConnectionFactory;
import org.forgerock.opendj.ldap.LdapException;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.containers.wait.strategy.WaitAllStrategy;

/**
 * Wren:DS test container.
 */
public class WrenDSContainer extends GenericContainer<WrenDSContainer> {

    private LDAPConnectionFactory connectionFactory;

    public WrenDSContainer() {
        this(System.getProperty("wrends.image", WrenDSConstants.WRENDS_IMAGE_NAME));
    }

    public WrenDSContainer(String imageName) {
        super(imageName);
        withExposedPorts(1389, 1636, 4444);
        withDefaultWait(Duration.ofMinutes(1));
    }

    public WrenDSContainer withDefaultWait(Duration startupTimeout) {
        return waitingFor(new WaitAllStrategy()
                .withStrategy(Wait.forLogMessage(
                        ".*Started listening for new connections on LDAP Connection Handler.*",
                        2 /* one for init and one for the actual startup */))
                .withStartupTimeout(startupTimeout));
    }

    public WrenDSContainer withSampleData() {
        return withSampleData(200);
    }

    public WrenDSContainer withSampleData(int size) {
        return withEnv("ADDITIONAL_SETUP_ARGS", "--sampleData " + size);
    }

    public int getLdapPort() {
        return getMappedPort(1389);
    }

    public int getAdminPort() {
        return getMappedPort(4444);
    }

    public synchronized LDAPConnectionFactory getLdapConnectionFactory() {
        if (connectionFactory == null) {
            connectionFactory = new LDAPConnectionFactory(getHost(), getLdapPort());
        }
        return connectionFactory;
    }

    public WrenDSConnection getLdapConnection() throws LdapException {
        return new WrenDSConnection(getLdapConnectionFactory().getConnection());
    }

    public WrenDSConnection getLdapConnection(String name, String password) throws LdapException {
        Connection connection = getLdapConnectionFactory().getConnection();
        connection.bind(name, password.toCharArray());
        return new WrenDSConnection(connection);
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
