import { APIGatewayProxyEventV2, APIGatewayProxyResult, APIGatewayProxyEventQueryStringParameters } from "aws-lambda";
import { v4 as uuidv4 } from "uuid";
import AWS from "aws-sdk";
import * as shared from "velux-alexa-integration-shared";

const dynamoDB = new AWS.DynamoDB.DocumentClient();
const AUTH_TABLE = "OAuthAuthorizationCodes";  // Ensure this DynamoDB table is created
const TOKEN_TABLE = "OAuthAccessTokens";  // Ensure this DynamoDB table is created
const USER_TABLE = "veluxusers";

// Handler for the Lambda function
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResult> => {
  const { rawPath, queryStringParameters, body, requestContext } = event;
  const httpMethod = requestContext.http.method;

  try {
    if (httpMethod === "GET" && rawPath === "/authorize") {
      return await handleAuthorize(queryStringParameters);
    } else if (httpMethod === "POST" && rawPath === "/token") {
      return await handleTokenExchange(body);
    } else if (httpMethod === "POST" && rawPath === "/register_user") {
        return await handleRegisterUser(body);
    } else {
      return {
        statusCode: 404,
        body: JSON.stringify({ error: "Unsupported operation" }),
      };
    }
  } catch (error) {
    console.error("Error occurred:", error);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: "Internal server error" }),
    };
  }
};

// Authorization handler to generate auth code
const handleAuthorize = async (params: APIGatewayProxyEventQueryStringParameters | undefined): Promise<APIGatewayProxyResult> => {
  if (!params || !params.client_id || !params.redirect_uri) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: "Missing required parameters" }),
    };
  }

  const { client_id, redirect_uri, state } = params;

  // Generate an authorization code
  const authCode = uuidv4();

  // Store the auth code in DynamoDB with expiration
  await dynamoDB.put({
    TableName: AUTH_TABLE,
    Item: {
      code: authCode,
      clientId: client_id,
      redirectUri: redirect_uri,
      expiresAt: Date.now() + 10 * 60 * 1000, // expires in 10 minutes
    },
  }).promise();

  // Redirect to the redirect_uri with the auth code
  const redirectLocation = `${redirect_uri}?code=${authCode}&state=${state || ""}`;
  return {
    statusCode: 302,
    headers: {
      Location: redirectLocation,
    },
    body: "",
  };
};

const handleTokenExchange = async (body: string | undefined | null): Promise<APIGatewayProxyResult> => {
    if (!body) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: "Missing request body" }),
      };
    }
  
    const parsedBody = JSON.parse(body);
    const { code, client_id, client_secret, redirect_uri } = parsedBody;
  
    // Validate the authorization code
    const result = await dynamoDB.get({
      TableName: AUTH_TABLE,
      Key: { code },
    }).promise();
  
    if (
      !result.Item ||
      result.Item.clientId !== client_id ||
      result.Item.redirectUri !== redirect_uri ||
      result.Item.expiresAt < Date.now()
    ) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: "Invalid or expired authorization code" }),
      };
    }
  
    // Retrieve the Velux User ID associated with the authorization code
    const veluxUserId = result.Item.veluxUserId;
  
    // Generate an access token
    const accessToken = uuidv4();
  
    // Store the access token along with the Velux User ID
    await dynamoDB.put({
      TableName: TOKEN_TABLE,
      Item: {
        token: accessToken,
        clientId: client_id,
        veluxUserId: veluxUserId, // Store the Velux User ID with the token
        createdAt: Date.now(),
        expiresAt: Date.now() + 60 * 60 * 1000, // 1 hour from now
      },
    }).promise();
  
    // Return the access token
    return {
      statusCode: 200,
      body: JSON.stringify({
        access_token: accessToken,
        token_type: "bearer",
        expires_in: 3600,
      }),
    };
  };
  

// Register Velux User handler
const handleRegisterUser = async (body: string | undefined | null): Promise<APIGatewayProxyResult> => {
    if (!body) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: "Missing request body" }),
      };
    }
  
    const parsedBody = JSON.parse(body);
    const { velux_user_id, velux_password, client_id, redirect_uri, state } = parsedBody;
  
    if (!velux_user_id || !velux_password || !client_id || !redirect_uri) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: "Missing required parameters" }),
      };
    }
  

    shared.state.storedUserId = velux_user_id;
    await shared.warmUp();
    shared.state.userData = { username: velux_user_id, password: velux_password, bridge: null, home_id: null };
    await shared.makeTokenRequest("password");   
  
    if (!shared.state.tokenData) {
        return {
          statusCode: 401,
          body: JSON.stringify({ error: "Error validating credentials against Velux backend!" }),
        };
      }

    // Store the Velux User ID and password in DynamoDB
    await dynamoDB.put({
      TableName: USER_TABLE,
      Item: {
        userid: velux_user_id,
        password: velux_password, // In a real implementation, make sure to hash/encrypt this password
        createdAt: Date.now(),
      },
    }).promise();
  
    // Generate an authorization code
    const authCode = uuidv4();
  
    // Store the authorization code and link it with the Velux User ID
    await dynamoDB.put({
      TableName: AUTH_TABLE,
      Item: {
        code: authCode,
        clientId: client_id,
        veluxUserId: velux_user_id,
        redirectUri: redirect_uri,
        expiresAt: Date.now() + 10 * 60 * 1000, // expires in 10 minutes
      },
    }).promise();
  
    // Redirect to the redirect_uri with the auth code
    const redirectLocation = `${redirect_uri}?code=${authCode}&state=${state || ""}`;
    return {
      statusCode: 302,
      headers: {
        Location: redirectLocation,
      },
      body: "",
    };
  };
  