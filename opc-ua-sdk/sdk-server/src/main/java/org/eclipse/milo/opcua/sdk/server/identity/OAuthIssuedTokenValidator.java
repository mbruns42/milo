/*
 * Copyright (c) 2018 Kevin Herron
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *   http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *   http://www.eclipse.org/org/documents/edl-v10.html.
 */

package org.eclipse.milo.opcua.sdk.server.identity;

import org.eclipse.milo.opcua.sdk.server.Session;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.channel.ServerSecureChannel;
import org.eclipse.milo.opcua.stack.core.types.structured.ActivateSessionRequest;
import org.eclipse.milo.opcua.stack.core.types.structured.IssuedIdentityToken;
import org.eclipse.milo.opcua.stack.core.types.structured.OAuthIdentityToken;
import org.eclipse.milo.opcua.stack.core.types.structured.SignatureData;
import org.eclipse.milo.opcua.stack.core.types.structured.UserTokenPolicy;

public class OAuthIssuedTokenValidator extends  AbstractIssuedTokenValidator {

    /**
     * Validate an {@link IssuedIdentityToken} and return an identity Object that represents the user.
     * <p>
     * This Object should implement equality in such a way that a subsequent identity validation for the same user
     * yields a comparable Object.
     *
     * @param channel        the {@link ServerSecureChannel} the request is arriving on.
     * @param session        the {@link Session} the request is arriving on.
     * @param token          the {@link IssuedIdentityToken}.
     * @param tokenPolicy    the {@link UserTokenPolicy} specified by the policyId in {@code token}.
     * @param tokenSignature the {@link SignatureData} sent in the {@link ActivateSessionRequest}.
     * @return an identity Object that represents the user.
     * @throws UaException if the token is invalid, rejected, or user access is denied.
     */
    protected Object validateOAuthIssuedIdentityToken(
        ServerSecureChannel channel,
        Session session,
        OAuthIdentityToken token,
        UserTokenPolicy tokenPolicy,
        SignatureData tokenSignature) throws UaException {
        throw new UaException(StatusCodes.Bad_IdentityTokenInvalid);
    }

}
