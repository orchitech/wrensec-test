package org.wrensecurity.wrenig.handler

import org.forgerock.http.protocol.Response
import org.forgerock.http.protocol.Status

def response = new Response(Status.OK)
response.setEntity('Hello from Groovy file')
return response
