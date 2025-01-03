import AWS from "aws-sdk";

const AUTH_TABLE = "OAuthAuthorizationCodes";
const TOKEN_TABLE = "OAuthAccessTokens";

export const storeAuthorizationCode = async (
  dynamoDB: AWS.DynamoDB.DocumentClient,
  code: string,
  clientId: string,
  redirectUri: string
) => {
  const params = {
    TableName: AUTH_TABLE,
    Item: {
      code,
      clientId,
      redirectUri,
      expiresAt: Date.now() + 10 * 60 * 1000, // 10 minutes from now
    },
  };

  await dynamoDB.put(params).promise();
};

export const validateAuthorizationCode = async (
  dynamoDB: AWS.DynamoDB.DocumentClient,
  code: string,
  clientId: string,
  redirectUri: string
): Promise<boolean> => {
  const params = {
    TableName: AUTH_TABLE,
    Key: { code },
  };

  const result = await dynamoDB.get(params).promise();
  if (
    result.Item &&
    result.Item.clientId === clientId &&
    result.Item.redirectUri === redirectUri &&
    result.Item.expiresAt > Date.now()
  ) {
    return true;
  }
  return false;
};

// Store Access Token
export const storeAccessToken = async (
  dynamoDB: AWS.DynamoDB.DocumentClient,
  token: string,
  clientId: string
) => {
  const params = {
    TableName: TOKEN_TABLE,
    Item: {
      token,
      clientId,
      createdAt: Date.now(),
      expiresAt: Date.now() + 60 * 60 * 1000, // 1 hour from now
    },
  };

  await dynamoDB.put(params).promise();
};
