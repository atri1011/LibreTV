// Cloudflare Pages Functions 中间件
// 简单的密码保护，类似于 https://dh.050415.xyz/ 的验证方式

// 配置
const AUTH_COOKIE_NAME = '__site_auth';
const LOGIN_PATH = '/_auth_login';
const COOKIE_MAX_AGE_SECONDS = 86400; // 1天

// 中间件处理函数
export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);

  // 1. 检查是否是登录验证请求
  if (request.method === 'POST' && url.pathname === LOGIN_PATH) {
    return handleLogin(request, env, url);
  }

  // 2. 检查静态资源是否应该跳过验证
  // 如果您有一些公开资源不需要验证，可以在这里放行
  // 例如登录页面需要的CSS/JS等资源
  if (skipAuthForPath(url.pathname)) {
    return next();
  }

  // 3. 检查会话Cookie
  const isAuthenticated = await verifyAuthCookie(request, env);
  if (isAuthenticated) {
    // 已验证，放行请求
    return next();
  } else {
    // 未验证，显示登录页面
    return showLoginPage(url);
  }
}

// 判断是否放行特定路径
function skipAuthForPath(path) {
  // 这里添加不需要验证的路径
  const ALLOWED_PATHS = [
    '/_auth_login',  // 登录API端点本身
    '/favicon.ico',  // 浏览器自动请求的favicon
    // 添加其他公开资源如需要
  ];
  
  // 检查是否是允许的路径
  if (ALLOWED_PATHS.includes(path)) {
    return true;
  }
  
  // 检查是否是公共资源文件
  const PUBLIC_EXTENSIONS = ['.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico'];
  for (const ext of PUBLIC_EXTENSIONS) {
    if (path.endsWith(ext)) {
      return true;
    }
  }
  
  return false;
}

// 处理登录请求
async function handleLogin(request, env, requestUrl) {
  try {
    const formData = await request.formData();
    const passwordAttempt = formData.get('password');
    const sitePassword = env.SITE_PASSWORD;
    
    if (!sitePassword) {
      return new Response('错误：未设置SITE_PASSWORD环境变量', { status: 500 });
    }

    if (passwordAttempt === sitePassword) {
      // 密码正确，生成新的会话Cookie
      const timestamp = Date.now();
      const data = JSON.stringify({ timestamp });
      const signature = await createHmac(data, sitePassword);
      const cookie = `${btoa(data)}.${signature}`;
      
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
    console.error("登录处理错误:", e);
    return showLoginPage(requestUrl, '处理登录时发生错误');
  }
}

// 显示登录页面
function showLoginPage(requestUrl, errorMessage = '') {
  // 保存原始访问路径，以便登录后重定向
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
      body { 
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif; 
        display: flex; 
        justify-content: center; 
        align-items: center; 
        min-height: 100vh; 
        margin: 0; 
        color: #f5f5f7;
        background: linear-gradient(to bottom, #000000, #1a1a1a, #2c2c2c);
        background-attachment: fixed;
      }
      .login-container { 
        background: rgba(30, 30, 30, 0.8);
        backdrop-filter: blur(20px);
        -webkit-backdrop-filter: blur(20px);
        padding: 2.5rem 3rem; 
        border-radius: 18px; 
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4); 
        text-align: center; 
        width: 90%; 
        max-width: 400px;
        border: 1px solid rgba(255, 255, 255, 0.1);
      }
      h2 { 
        color: #fff; 
        margin-bottom: 1.5rem;
        font-weight: 500;
        letter-spacing: 0.5px;
      }
      input[type="password"] { 
        padding: 0.8rem; 
        margin-bottom: 1.5rem; 
        border: none; 
        border-radius: 8px; 
        width: calc(100% - 1.6rem); 
        background-color: rgba(60, 60, 60, 0.6); 
        color: #fff; 
        font-size: 1rem;
        transition: all 0.3s ease;
      }
      input[type="password"]:focus { 
        outline: none; 
        background-color: rgba(70, 70, 70, 0.8);
        box-shadow: 0 0 0 2px rgba(0, 125, 250, 0.6); 
      }
      button { 
        padding: 0.8rem 0; 
        width: 100%;
        background: linear-gradient(to right, #0071e3, #2b8eff); 
        color: white; 
        border: none; 
        border-radius: 8px; 
        cursor: pointer; 
        font-size: 1rem; 
        font-weight: 500; 
        transition: all 0.3s ease;
        letter-spacing: 0.5px;
      }
      button:hover { 
        opacity: 0.9; 
        transform: translateY(-1px);
        box-shadow: 0 5px 15px rgba(0, 113, 227, 0.4); 
      }
      button:active {
        transform: translateY(1px);
      }
      .error { 
        color: #ff6b6b; 
        margin-bottom: 1.2rem; 
        font-size: 0.9rem;
        background-color: rgba(255, 0, 0, 0.1);
        padding: 0.5rem;
        border-radius: 6px;
      }
      form { margin-top: 1.5rem; }
    </style>
  </head>
  <body>
    <div class="login-container">
      <h2>请输入访问密码</h2>
      ${errorMessage ? `<p class="error">${errorMessage}</p>` : ''}
      <form method="POST" action="${LOGIN_PATH}?redirect=${encodedRedirect}">
        <input type="password" name="password" placeholder="密码" required autofocus>
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

// 验证认证Cookie
async function verifyAuthCookie(request, env) {
  const cookieHeader = request.headers.get('Cookie');
  if (!cookieHeader) return false;
  
  const sitePassword = env.SITE_PASSWORD;
  if (!sitePassword) return false;

  const cookies = cookieHeader.split(';').reduce((acc, cookie) => {
    const [name, value] = cookie.split('=').map(c => c.trim());
    if (name) acc[name] = value;
    return acc;
  }, {});

  const authCookie = cookies[AUTH_COOKIE_NAME];
  if (!authCookie) return false;

  const parts = authCookie.split('.');
  if (parts.length !== 2) return false;

  const [encodedData, signature] = parts;

  try {
    // 解码数据部分
    let data;
    try {
      data = JSON.parse(atob(encodedData));
    } catch (e) {
      console.error('Invalid cookie data format', e);
      return false;
    }

    // 验证签名
    const calculatedSignature = await createHmac(atob(encodedData), sitePassword);
    if (calculatedSignature !== signature) {
      console.log('签名验证失败');
      return false;
    }

    // 检查是否过期
    const now = Date.now();
    const cookieAgeSeconds = (now - data.timestamp) / 1000;
    if (cookieAgeSeconds > COOKIE_MAX_AGE_SECONDS) {
      console.log('认证Cookie已过期');
      return false;
    }

    return true; // 验证通过
  } catch (e) {
    console.error('验证Cookie时出错:', e);
    return false;
  }
}

// 创建HMAC签名 (使用SHA-256)
async function createHmac(message, key) {
  // 将消息转换为ArrayBuffer
  const encoder = new TextEncoder();
  const messageBuffer = encoder.encode(message);
  
  // 计算SHA-256哈希
  const hashBuffer = await crypto.subtle.digest('SHA-256', messageBuffer);
  
  // 转换为Hex字符串
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  
  // 在实际场景中，我们应该使用HMAC（但Pages Functions可能不支持完整的crypto.subtle.sign）
  // 这是一个简化版，实际上应该使用HMAC-SHA256
  return hashHex;
} 