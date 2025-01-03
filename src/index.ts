import {
  APIGatewayProxyEventV2,
  APIGatewayProxyResult,
  APIGatewayProxyEventQueryStringParameters,
} from "aws-lambda";
import { v4 as uuidv4 } from "uuid";
import AWS from "aws-sdk";
import * as shared from "velux-alexa-integration-shared";
import {
  SkillType,
  UserData,
} from "velux-alexa-integration-shared/dist/interfaces/interfaces.mjs";

const dynamoDB = new AWS.DynamoDB.DocumentClient();

export const handler = async (
  event: APIGatewayProxyEventV2
): Promise<APIGatewayProxyResult> => {
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
      console.error("An unsupported operation was called: ", rawPath);
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

const handleAuthorize = async (
  params: APIGatewayProxyEventQueryStringParameters | undefined
): Promise<APIGatewayProxyResult> => {
  if (!params || !params.client_id || !params.redirect_uri) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: "Missing required parameters" }),
    };
  }

  const { client_id, redirect_uri, state } = params;

  const authCode = uuidv4();

  await dynamoDB
    .put({
      TableName: shared.Table.AUTH,
      Item: {
        code: authCode,
        clientId: client_id,
        redirectUri: redirect_uri,
        expiresAt: Date.now() + 10 * 60 * 1000, // expires in 10 minutes
      },
    })
    .promise();

  const redirectLocation = `${redirect_uri}?code=${authCode}&state=${
    state || ""
  }`;
  return {
    statusCode: 302,
    headers: {
      Location: redirectLocation,
    },
    body: "",
  };
};

const handleTokenExchange = async (
  body: string | undefined | null
): Promise<APIGatewayProxyResult> => {
  if (!body) {
    return {
      statusCode: 400,
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ error: "Missing request body" }),
    };
  }

  const decodedBody = Buffer.from(body, "base64").toString("utf-8");

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
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ error: "Missing required parameters" }),
    };
  }

  if (grant_type !== "authorization_code") {
    console.error("Invalid grant type");
    return {
      statusCode: 400,
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ error: "Invalid grant type" }),
    };
  }

  const result = await dynamoDB
    .get({
      TableName: shared.Table.AUTH,
      Key: { code },
    })
    .promise();

  if (!result.Item || result.Item.expiresAt < Date.now()) {
    console.error("Invalid or expired authorization code");
    return {
      statusCode: 400,
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ error: "Invalid or expired authorization code" }),
    };
  }

  const veluxUserId = result.Item.veluxUserId;

  const accessToken = uuidv4();

  await dynamoDB
    .put({
      TableName: shared.Table.TOKEN,
      Item: {
        token: accessToken,
        clientId: client_id,
        veluxUserId: veluxUserId,
        createdAt: Date.now(),
        expiresAt: Date.now() + 60 * 60 * 1000, // 1 hour expiry
      },
    })
    .promise();

  return {
    statusCode: 200,
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      access_token: accessToken,
      token_type: "bearer",
      expires_in: 3600, // 1 hour in seconds
    }),
  };
};

const handleRegisterUser = async (
  body: string | undefined | null
): Promise<APIGatewayProxyResult> => {
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

  await shared.warmUp();
  shared.state.skillType = SkillType.SmartHome;

  shared.state.userData = {
    username: velux_user_id,
    password: velux_password,
    bridge: null,
    home_id: null,
    access_token: null,
    refresh_token: null,
  };

  const token = await shared.makeTokenRequest("password");

  if (!shared.state.tokenData) {
    return {
      statusCode: 401,
      body: JSON.stringify({
        error: "Error validating credentials against Velux backend!",
      }),
    };
  }

  const homeInfoJSON = await shared.getHomeInfoWithRetry();

  const homeData = homeInfoJSON.data;

  const homeId = homeData.body.homes[0].id;
  const bridge = homeData.body.homes[0].modules.find(
    (module) => module.type === "NXG"
  )?.id!;

  console.log("Bridge: " + bridge);

  const userData: UserData = {
    username: velux_user_id,
    password: velux_password,
    home_id: homeId,
    bridge: bridge,
    access_token: token.AccessToken,
    refresh_token: token.RefreshToken,
  };

  const dbitem = {
    ...userData,
    createdAt: Date.now(),
  };

  await dynamoDB
    .put({
      TableName: shared.Table.USER,
      Item: dbitem,
    })
    .promise();

  const authCode = uuidv4();

  await dynamoDB
    .put({
      TableName: shared.Table.AUTH,
      Item: {
        code: authCode,
        veluxUserId: velux_user_id,
        expiresAt: Date.now() + 10 * 60 * 1000, // expires in 10 minutes
      },
    })
    .promise();

  return {
    statusCode: 200,
    body: JSON.stringify({
      message: {
        code: authCode,
      },
      homeInfo: homeData,
    }),
  };
};
