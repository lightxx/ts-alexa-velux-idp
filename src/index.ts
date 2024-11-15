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
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ error: "Missing request body" }),
        };
    }

    const decodedBody = Buffer.from(body, 'base64').toString('utf-8');

    console.log("Decoded Body: " + decodedBody);

    const params = new URLSearchParams(decodedBody);
    const code = params.get("code");
    const client_id = params.get("client_id");
    const redirect_uri = params.get("redirect_uri");
    const grant_type = params.get("grant_type");

    if (!code || !client_id || !redirect_uri || !grant_type) {
        console.error("Missing required parameters");
        return {
            statusCode: 400,
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ error: "Missing required parameters" }),
        };
    }

    if (grant_type !== "authorization_code") {
        console.error("Invalid grant type");
        return {
            statusCode: 400,
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ error: "Invalid grant type" }),
        };
    }

    const result = await dynamoDB.get({
        TableName: AUTH_TABLE,
        Key: { code },
    }).promise();

    if (
        !result.Item ||  result.Item.expiresAt < Date.now()
    ) {
        console.error("Invalid or expired authorization code");
        return {
            statusCode: 400,
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ error: "Invalid or expired authorization code" }),
        };
    }

    const veluxUserId = result.Item.veluxUserId;

    // Generate a new access token
    const accessToken = uuidv4();

    // Store the access token
    await dynamoDB.put({
        TableName: TOKEN_TABLE,
        Item: {
            token: accessToken,
            clientId: client_id,
            veluxUserId: veluxUserId,
            createdAt: Date.now(),
            expiresAt: Date.now() + 60 * 60 * 1000, // 1 hour expiry
        },
    }).promise();

    // Return the access token
    return {
        statusCode: 200,
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            access_token: accessToken,
            token_type: "bearer",
            expires_in: 3600, // 1 hour in seconds
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
    const { velux_user_id, velux_password } = parsedBody;
  
    if (!velux_user_id || !velux_password) {
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
      
    await dynamoDB.put({
      TableName: USER_TABLE,
      Item: {
        userid: velux_user_id,
        password: velux_password, 
        createdAt: Date.now(),
      },
    }).promise();
  
    const authCode = uuidv4();
  
    await dynamoDB.put({
      TableName: AUTH_TABLE,
      Item: {
        code: authCode,
        veluxUserId: velux_user_id,
        expiresAt: Date.now() + 10 * 60 * 1000, // expires in 10 minutes
      },
    }).promise();
  
    const homeInfoJSON = await shared.getHomeInfo();

    const homeData = homeInfoJSON.data;

    return {
        statusCode: 200, 
        body: JSON.stringify({
          message: {
            code: authCode
          },          
          homeInfo: homeData
        }),
      };
  };
  