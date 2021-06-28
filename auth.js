"use strict";
// From: https://github.com/auth0-samples/jwt-rsa-aws-custom-authorizer

const jwt = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");

const TOKEN_ISSUER =
  "https://cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_UAoFp1sxj";
const JWKS_URI =
  "https://cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_UAoFp1sxj/.well-known/jwks.json";
const AUDIENCE = "";

const jwtOptions = {
  audience: AUDIENCE,
  issuer: TOKEN_ISSUER,
};

const client = jwksClient({
  cache: true,
  rateLimit: true,
  jwksRequestsPerMinute: 10, // Default value
  jwksUri: JWKS_URI,
});

const getPolicyDocument = (effect, resource) => {
  const policyDocument = {
    Version: "2012-10-17", // default version
    Statement: [
      {
        Action: "execute-api:Invoke", // default action
        Effect: effect,
        Resource: resource,
      },
    ],
  };
  return policyDocument;
};

const getToken = (params) => {
  if (!params.type || params.type !== "TOKEN") {
    throw new Error('Expected "event.type" parameter to have value "TOKEN"');
  }

  const tokenString = params.authorizationToken;
  if (!tokenString) {
    throw new Error('Expected "event.authorizationToken" parameter to be set');
  }

  const match = tokenString.match(/^Bearer (.*)$/);
  if (!match || match.length < 2) {
    throw new Error(
      `Invalid Authorization token - ${tokenString} does not match "Bearer .*"`
    );
  }
  return match[1];
};

const authenticate = async (params) => {
  console.log(params);
  const token = getToken(params);

  const decoded = jwt.decode(token, { complete: true });
  if (!decoded || !decoded.header || !decoded.header.kid) {
    throw new Error("Invalid token");
  }

  const key = await client.getSigningKey(decoded.header.kid);
  const signingKey = key.publicKey || key.rsaPublicKey;
  jwt.verify(token, signingKey, jwtOptions);

  return {
    principalId: decoded.sub,
    policyDocument: getPolicyDocument("Allow", params.methodArn),
    context: { scope: decoded.scope },
  };
};

module.exports.handler = async (event, context, callback) => {
  let data;
  try {
    data = await authenticate(event);
  } catch (err) {
    console.log(err);
    return context.fail("Unauthorized");
  }
  return data;
};
