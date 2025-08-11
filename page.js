// EdgeOne Pages Function export
export function onRequest(context) {
  return handleRequest(context.request);
}

var R2_CONFIG = {
  region: 'auto',
  service: 's3',
  accountId: '',
  accessKeyId: '',
  secretAccessKey: '',
  bucketName: ''
};

// 工具函数
function arrayBufferToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function stringToUint8Array(str) {
  return new TextEncoder().encode(str);
}

async function sha256Hash(message) {
  var msgBuffer = typeof message === 'string' ? stringToUint8Array(message) : message;
  var hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  return arrayBufferToHex(hashBuffer);
}

async function hmacSha256(key, message) {
  var keyBuffer = typeof key === 'string' ? stringToUint8Array(key) : key;
  var msgBuffer = typeof message === 'string' ? stringToUint8Array(message) : message;
  
  var cryptoKey = await crypto.subtle.importKey(
    'raw', keyBuffer, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  
  var signature = await crypto.subtle.sign('HMAC', cryptoKey, msgBuffer);
  return new Uint8Array(signature);
}

async function getSignatureKey(key, dateStamp, regionName, serviceName) {
  var kDate = await hmacSha256('AWS4' + key, dateStamp);
  var kRegion = await hmacSha256(kDate, regionName);
  var kService = await hmacSha256(kRegion, serviceName);
  var kSigning = await hmacSha256(kService, 'aws4_request');
  return kSigning;
}

function formatDateISO8601(date) {
  return date.toISOString().replace(/[:-]|\.\d{3}/g, '');
}

function formatDateYYYYMMDD(date) {
  return date.toISOString().slice(0, 10).replace(/-/g, '');
}

// 执行签名的R2请求
async function makeR2Request(method, path, queryParams) {
  var now = new Date();
  var amzDate = formatDateISO8601(now);
  var dateStamp = formatDateYYYYMMDD(now);
  
  var canonicalUri = path;
  var host = R2_CONFIG.bucketName + '.' + R2_CONFIG.accountId + '.r2.cloudflarestorage.com';
  
  // 构建查询字符串
  var canonicalQueryString = '';
  if (queryParams && Object.keys(queryParams).length > 0) {
    var queryParts = [];
    var keys = Object.keys(queryParams).sort();
    for (var i = 0; i < keys.length; i++) {
      var key = keys[i];
      var value = queryParams[key];
      queryParts.push(encodeURIComponent(key) + '=' + encodeURIComponent(value));
    }
    canonicalQueryString = queryParts.join('&');
  }
  
  // 计算空请求体的哈希
  var payloadHash = await sha256Hash('');
  
  // 构建头部（必须按字母顺序）
  var headers = {
    'host': host,
    'x-amz-content-sha256': payloadHash,
    'x-amz-date': amzDate
  };
  
  var signedHeaders = 'host;x-amz-content-sha256;x-amz-date';
  
  // 构建规范头部字符串
  var canonicalHeaders = 
    'host:' + headers.host + '\n' +
    'x-amz-content-sha256:' + headers['x-amz-content-sha256'] + '\n' +
    'x-amz-date:' + headers['x-amz-date'] + '\n';

  // 构建规范请求
  var canonicalRequest = 
    method + '\n' +
    canonicalUri + '\n' +
    canonicalQueryString + '\n' +
    canonicalHeaders + '\n' +
    signedHeaders + '\n' +
    payloadHash;

  // 计算规范请求哈希
  var canonicalRequestHash = await sha256Hash(canonicalRequest);
  
  // 构建凭证范围
  var credentialScope = dateStamp + '/' + R2_CONFIG.region + '/' + R2_CONFIG.service + '/aws4_request';
  
  // 构建待签名字符串
  var stringToSign = 
    'AWS4-HMAC-SHA256\n' +
    amzDate + '\n' +
    credentialScope + '\n' +
    canonicalRequestHash;

  // 生成签名
  var signingKey = await getSignatureKey(
    R2_CONFIG.secretAccessKey,
    dateStamp,
    R2_CONFIG.region,
    R2_CONFIG.service
  );
  
  var signatureBytes = await hmacSha256(signingKey, stringToSign);
  var signature = arrayBufferToHex(signatureBytes);

  // 构建授权头
  var authorizationHeader = 
    'AWS4-HMAC-SHA256 Credential=' + R2_CONFIG.accessKeyId + '/' + credentialScope + 
    ', SignedHeaders=' + signedHeaders + 
    ', Signature=' + signature;

  // 构建完整URL
  var url = 'https://' + host + canonicalUri;
  if (canonicalQueryString) {
    url += '?' + canonicalQueryString;
  }

  // 发送请求
  return fetch(url, {
    method: method,
    headers: {
      'Authorization': authorizationHeader,
      'X-Amz-Date': amzDate,
      'X-Amz-Content-Sha256': payloadHash,
      'Host': host
    }
  });
}

// 列出指定前缀的对象
async function listR2Objects(prefix) {
  var queryParams = {};
  if (prefix) {
    queryParams.prefix = prefix;
  }
  
  return makeR2Request('GET', '/', queryParams);
}

// 获取指定对象
async function getR2Object(key) {
  // 正确编码路径：只编码文件名部分，保留路径分隔符
  var encodedKey = key.split('/').map(function(part) {
    return encodeURIComponent(part);
  }).join('/');
  
  return makeR2Request('GET', '/' + encodedKey);
}

// 从XML响应中提取对象键列表
function extractObjectKeys(xmlText) {
  var keys = [];
  var keyMatches = xmlText.matchAll(/<Key>([^<]+)<\/Key>/g);
  
  for (var match of keyMatches) {
    keys.push(match[1]);
  }
  
  return keys;
}

// 根据文件扩展名获取MIME类型
function getMimeType(filename) {
  var ext = filename.toLowerCase().split('.').pop();
  var mimeTypes = {
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'png': 'image/png',
    'gif': 'image/gif',
    'webp': 'image/webp',
    'bmp': 'image/bmp',
    'svg': 'image/svg+xml'
  };
  return mimeTypes[ext] || 'image/jpeg';
}

async function handleRequest(request) {
  try {
    var url = new URL(request.url);
    var imgType = url.searchParams.get('img');
    
    // 根据查询参数确定前缀
    var prefix = '';
    if (imgType === 'h') {
      prefix = 'ri/h/';
    } else if (imgType === 'v') {
      prefix = 'ri/v/';
    } else {
      // 显示使用说明
      var helpText = '🖼️ 随机图片展示器\n\n';
      helpText += '使用方法:\n';
      helpText += '• ?img=h - 获取横屏随机图片\n';
      helpText += '• ?img=v - 获取竖屏随机图片\n\n';
      
      return new Response(helpText, {
        status: 200,
        headers: { 
          'Content-Type': 'text/plain; charset=utf-8',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }

    // 获取对象列表
    var listResponse = await listR2Objects(prefix);
    
    if (!listResponse.ok) {
      var errorText = await listResponse.text();
      return new Response('❌ 获取图片列表失败: ' + errorText, {
        status: listResponse.status,
        headers: { 'Content-Type': 'text/plain; charset=utf-8' }
      });
    }

    var xmlText = await listResponse.text();
    var objectKeys = extractObjectKeys(xmlText);

    if (objectKeys.length === 0) {
      var emptyMessage = imgType === 'h' ? '📭 未找到横屏图片' : '📭 未找到竖屏图片';
      return new Response(emptyMessage, { 
        status: 404,
        headers: { 'Content-Type': 'text/plain; charset=utf-8' }
      });
    }

    // 随机选择一个图片
    var randomKey = objectKeys[Math.floor(Math.random() * objectKeys.length)];
    
    // 添加调试信息
    console.log('选中的图片键:', randomKey);
    console.log('图片总数:', objectKeys.length);
    console.log('前5个图片键:', objectKeys.slice(0, 5));
    
    // 获取图片对象
    var objectResponse = await getR2Object(randomKey);
    
    if (!objectResponse.ok) {
      var errorText = await objectResponse.text();
      var errorDetails = '❌ 获取图片失败\n\n';
      errorDetails += '状态码: ' + objectResponse.status + '\n';
      errorDetails += '图片键: ' + randomKey + '\n';
      errorDetails += '编码后路径: /' + randomKey.split('/').map(function(part) {
        return encodeURIComponent(part);
      }).join('/') + '\n';
      errorDetails += '错误详情: ' + errorText + '\n';
      
      return new Response(errorDetails, { 
        status: objectResponse.status,
        headers: { 'Content-Type': 'text/plain; charset=utf-8' }
      });
    }

    // 获取图片数据
    var imageData = await objectResponse.arrayBuffer();
    var contentType = getMimeType(randomKey);

    // 返回图片
    return new Response(imageData, {
      status: 200,
      headers: {
        'Content-Type': contentType,
        'Cache-Control': 'public, max-age=3600',
        'Access-Control-Allow-Origin': '*',
        'X-Image-Key': randomKey,
        'X-Total-Images': objectKeys.length.toString()
      }
    });

  } catch (error) {
    var errorDetails = '❌ 内部错误\n\n';
    errorDetails += '错误消息: ' + error.message + '\n';
    errorDetails += '错误堆栈: ' + error.stack + '\n';
    errorDetails += '请求地址: ' + request.url + '\n';
    errorDetails += '时间戳: ' + new Date().toISOString();
    
    return new Response(errorDetails, {
      status: 500,
      headers: { 'Content-Type': 'text/plain; charset=utf-8' }
    });
  }
}
