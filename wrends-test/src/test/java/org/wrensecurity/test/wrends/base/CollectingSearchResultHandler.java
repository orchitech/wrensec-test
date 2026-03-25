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

import java.util.ArrayList;
import java.util.List;
import org.forgerock.opendj.ldap.SearchResultHandler;
import org.forgerock.opendj.ldap.responses.SearchResultEntry;
import org.forgerock.opendj.ldap.responses.SearchResultReference;

/**
 * Search result handler that simply collects all entries in an internal list buffer.
 */
public class CollectingSearchResultHandler implements SearchResultHandler {

    private final List<SearchResultEntry> entries = new ArrayList<>();

    @Override
    public synchronized boolean handleEntry(SearchResultEntry entry) {
        entries.add(entry);
        return true;
    }

    @Override
    public boolean handleReference(SearchResultReference reference) {
        return true;
    }

    public synchronized List<SearchResultEntry> getEntries() {
        return List.copyOf(entries);
    }

}
