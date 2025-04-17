'use strict';

// --- 配置 --- 
// 会话 Cookie 名称 (可以自定义)
const AUTH_COOKIE_NAME = '__site_auth';
// 登录验证路径 (可以自定义, 但要与 HTML 表单中的 action 匹配)
const LOGIN_PATH = '/_cf_auth_login';
// Cookie 有效期 (秒), 默认 1 天
const COOKIE_MAX_AGE_SECONDS = 86400; 
// --- 配置结束 ---

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request, event))
});

async function handleRequest(request, event) {
  const url = new URL(request.url);

  // 0. 从环境变量获取密码 (必须在 Cloudflare 中设置名为 SITE_PASSWORD 的 Secret)
  const sitePassword = env.SITE_PASSWORD;
  if (!sitePassword) {
    // 如果未设置密码环境变量，直接返回错误提示，防止意外暴露网站
    return new Response('Cloudflare Worker 配置错误：未设置 SITE_PASSWORD 环境变量。', { status: 500 });
  }

  // 1. 检查是否是登录验证请求
  if (request.method === 'POST' && url.pathname === LOGIN_PATH) {
    return handleLogin(request, sitePassword, url);
  }

  // 2. 检查会话 Cookie
  const isAuthenticated = await verifyAuthCookie(request, sitePassword); // 使用密码作为签名密钥的一部分
  if (isAuthenticated) {
    // 已验证，允许访问源站
    // 使用 event.passThroughOnException() 可以在 Worker 出错时回退到 Cloudflare 默认行为
    // event.passThroughOnException();
    // return fetch(request);
    // 改为直接获取源站内容，避免某些情况下 passThrough 的问题
    const originResponse = await fetch(request);
    return originResponse;
  } else {
    // 未验证或 Cookie 无效/过期，显示登录页面
    return showLoginPage(url);
  }
}

// 处理登录请求
async function handleLogin(request, sitePassword, requestUrl) {
  try {
    const formData = await request.formData();
    const passwordAttempt = formData.get('password');

    if (passwordAttempt === sitePassword) {
      // 密码正确，生成新的会话 Cookie
      const cookie = await generateAuthCookie(sitePassword); // 使用密码签名
      const redirectUrl = requestUrl.searchParams.get('redirect') || '/';

      const headers = new Headers({
        'Location': redirectUrl,
        'Set-Cookie': `${AUTH_COOKIE_NAME}=${cookie}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${COOKIE_MAX_AGE_SECONDS}`
      });

      return new Response(null, { status: 302, headers });
    } else {
      // 密码错误，重新显示登录页并附带错误信息
      return showLoginPage(requestUrl, '密码错误');
    }
  } catch (e) {
    console.error("Login handling error:", e);
    return showLoginPage(requestUrl, '处理登录时发生错误');
  }
}

// 显示登录页面
function showLoginPage(requestUrl, errorMessage = '') {
  // 保存用户原始想访问的路径，以便登录后重定向
  const originalPath = requestUrl.pathname === LOGIN_PATH ? '/' : requestUrl.pathname + requestUrl.search;
  const encodedRedirect = encodeURIComponent(originalPath);

  const html = `
  <!DOCTYPE html>
  <html lang="zh-CN">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>访问验证</title>
    <style>
      body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; background-color: #222; color: #eee; margin: 0; }
      .login-container { background-color: #333; padding: 2rem 3rem; border-radius: 8px; box-shadow: 0 5px 15px rgba(0,0,0,0.3); text-align: center; width: 90%; max-width: 400px; }
      h2 { color: #00ccff; margin-bottom: 1.5rem; }
      input[type="password"] { padding: 0.8rem; margin-bottom: 1rem; border: 1px solid #555; border-radius: 4px; width: calc(100% - 1.6rem); background-color: #444; color: #eee; font-size: 1rem; }
      input[type="password"]:focus { outline: none; border-color: #00ccff; box-shadow: 0 0 5px rgba(0, 204, 255, 0.5); }
      button { padding: 0.8rem 1.5rem; background: linear-gradient(to right, #00aaff, #00ccff); color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 1rem; font-weight: bold; transition: all 0.3s ease; }
      button:hover { opacity: 0.9; box-shadow: 0 3px 10px rgba(0, 204, 255, 0.4); }
      .error { color: #ff6666; margin-bottom: 1rem; font-size: 0.9rem; }
      form { margin-top: 1rem; }
    </style>
  </head>
  <body>
    <div class="login-container">
      <h2>请输入访问密码</h2>
      ${errorMessage ? `<p class="error">${errorMessage}</p>` : ''}
      <form method="POST" action="${LOGIN_PATH}?redirect=${encodedRedirect}">
        <input type="password" name="password" placeholder="密码" required>
        <br>
        <button type="submit">验 证</button>
      </form>
    </div>
  </body>
  </html>
  `;
  return new Response(html, {
    status: 401, // Unauthorized
    headers: { 'Content-Type': 'text/html;charset=UTF-8' },
  });
}

// --- Cookie 签名与验证 (使用 HMAC-SHA256) ---

// 将字符串转换为 ArrayBuffer
function str2ab(str) {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

// 将 ArrayBuffer 转换为 Base64 URL Safe 字符串
function ab2b64url(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// 将 Base64 URL Safe 字符串转换为 ArrayBuffer
function b64url2ab(b64url) {
    b64url = b64url.replace(/-/g, '+').replace(/_/g, '/');
    while (b64url.length % 4) {
        b64url += '=';
    }
    const binStr = atob(b64url);
    const buf = new ArrayBuffer(binStr.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0; i < binStr.length; i++) {
        bufView[i] = binStr.charCodeAt(i);
    }
    return buf;
}

// 获取用于签名的 CryptoKey
async function getSigningKey(secret) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    str2ab(secret), // 使用提供的密码作为原始密钥材料
    { name: 'HMAC', hash: 'SHA-256' },
    false, // not extractable
    ['sign', 'verify']
  );
  return keyMaterial;
}

// 生成带有签名的认证 Cookie 值
async function generateAuthCookie(secret) {
  const key = await getSigningKey(secret);
  const data = JSON.stringify({ 
    timestamp: Date.now(), 
    // 可以添加其他需要保护的数据, 如 IP 地址
    // ip: request.headers.get('CF-Connecting-IP') 
  });
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    str2ab(data) // 签名 JSON 数据
  );
  // 组合数据和签名，编码为 base64url
  const encodedData = ab2b64url(str2ab(data));
  const encodedSignature = ab2b64url(signature);
  return `${encodedData}.${encodedSignature}`;
}

// 验证认证 Cookie
async function verifyAuthCookie(request, secret) {
  const cookieHeader = request.headers.get('Cookie');
  if (!cookieHeader) return false;

  const cookies = cookieHeader.split(';').reduce((acc, cookie) => {
    const [name, value] = cookie.split('=').map(c => c.trim());
    if (name) acc[name] = value;
    return acc;
  }, {});

  const authCookie = cookies[AUTH_COOKIE_NAME];
  if (!authCookie) return false;

  const parts = authCookie.split('.');
  if (parts.length !== 2) return false; // 必须是 data.signature 格式

  const [encodedData, encodedSignature] = parts;

  try {
    const key = await getSigningKey(secret);
    const dataBuffer = b64url2ab(encodedData);
    const signatureBuffer = b64url2ab(encodedSignature);

    const isValid = await crypto.subtle.verify(
      'HMAC',
      key,
      signatureBuffer,
      dataBuffer
    );

    if (!isValid) {
      console.log('HMAC verification failed');
      return false;
    }

    // 签名有效，解析数据检查时间戳
    const dataStr = String.fromCharCode(...new Uint8Array(dataBuffer));
    const data = JSON.parse(dataStr);

    const now = Date.now();
    const cookieAgeSeconds = (now - data.timestamp) / 1000;

    if (cookieAgeSeconds > COOKIE_MAX_AGE_SECONDS) {
      console.log('Auth cookie expired');
      return false; // Cookie 已过期
    }
    
    // 如果包含 IP 检查，可以在这里进行
    // if (data.ip && data.ip !== request.headers.get('CF-Connecting-IP')) {
    //   console.log('IP mismatch');
    //   return false;
    // }

    return true; // 签名有效且未过期
  } catch (e) {
    console.error('Error verifying cookie:', e);
    return false;
  }
}

// 将环境变量绑定到 Worker (Cloudflare 会自动处理)
// 需要在 Cloudflare Dashboard 中配置名为 'SITE_PASSWORD' 的 Secret
// const env = {
//   SITE_PASSWORD: 'your_password_here' // 仅用于本地测试，部署时 Cloudflare 会注入
// }; 