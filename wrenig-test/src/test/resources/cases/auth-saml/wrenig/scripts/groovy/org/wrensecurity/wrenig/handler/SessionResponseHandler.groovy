package org.wrensecurity.wrenig.handler

import org.forgerock.http.protocol.Response
import org.forgerock.http.protocol.Status

def response = new Response(Status.OK)
def data = [
    'session': 'wrenig-session',
    'username': session.username[0]
]
response.setEntity(data)
return response
