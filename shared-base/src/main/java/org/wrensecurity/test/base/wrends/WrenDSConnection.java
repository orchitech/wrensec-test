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

import static org.forgerock.opendj.ldap.requests.Requests.newSearchRequest;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.forgerock.opendj.ldap.Connection;
import org.forgerock.opendj.ldap.LdapException;
import org.forgerock.opendj.ldap.SearchScope;
import org.forgerock.opendj.ldap.requests.SearchRequest;
import org.forgerock.opendj.ldap.responses.Result;
import org.forgerock.opendj.ldap.responses.SearchResultEntry;

/**
 * Test-oriented LDAP connection wrapper.
 */
public class WrenDSConnection implements AutoCloseable {

    private final Connection connection;

    /**
     * Create new connection wrapper for the given connection.
     */
    public WrenDSConnection(Connection connection) {
        this.connection = connection;
    }

    /**
     * Simple search wrapper with no custom search result or entry processing.
     */
    public List<SearchResultEntry> search(String name, SearchScope scope, String filter, String... attributes)
            throws LdapException {
        SearchRequest request = newSearchRequest(name, scope, filter, attributes);

        List<SearchResultEntry> entries = new ArrayList<>();
        Result result = connection.search(request, entries);
        if (!result.isSuccess()) {
            throw new IllegalStateException("Unexpected search result: " + result);
        }
        return entries;
    }

    /**
     * Get the underlying LDAP connection.
     */
    public Connection unwrap() {
        return connection;
    }

    @Override
    public void close() throws IOException {
        connection.close();
    }

}
