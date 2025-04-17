// functions/_middleware.js

// Helper function for Basic Auth comparison
function isAuthorized(request, env) {
  // Get the expected username and password from environment variables
  const expectedUsername = env.USERNAME;
  const expectedPassword = env.PASSWORD;

  if (!expectedUsername || !expectedPassword) {
    // If environment variables are not set, deny access
    console.error("Basic Auth environment variables USERNAME or PASSWORD not set.");
    return false;
  }

  // Get the Authorization header
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    return false; // No or invalid Authorization header
  }

  // Decode the base64 credentials
  const base64Credentials = authHeader.substring('Basic '.length);
  let decodedCredentials;
  try {
    decodedCredentials = atob(base64Credentials); // atob is available in Workers
  } catch (e) {
    return false; // Invalid base64 encoding
  }


  // Split username and password
  const [username, password] = decodedCredentials.split(':');

  // Check if credentials match the environment variables
  return username === expectedUsername && password === expectedPassword;
}

export async function onRequest(context) {
  const { request, env, next } = context;

  // Check if the request is authorized
  if (isAuthorized(request, env)) {
    // Authorized: proceed to the next function or serve the asset
    return await next();
  } else {
    // Unauthorized: return a 401 response
    return new Response('Unauthorized', {
      status: 401,
      headers: {
        // Prompt the browser to ask for credentials
        'WWW-Authenticate': 'Basic realm="Restricted Access"',
      },
    });
  }
} 