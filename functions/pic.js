// EdgeOne Pages Function export
export function onRequest(context) {
  return handleRequest(context.request);
}

// 配置项
var CONFIG = {
  maxHorizontalImageNumber: 833,  // 横屏图片最大编号
  maxVerticalImageNumber: 2942     // 竖屏图片最大编号
};

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
  return mimeTypes[ext] || 'image/webp';
}

// 检测是否为移动设备
function isMobileDevice(userAgent) {
  if (!userAgent) return false;
  
  var mobileKeywords = [
    'Mobile', 'Android', 'iPhone', 'iPad', 'iPod', 'BlackBerry', 
    'Windows Phone', 'Opera Mini', 'IEMobile', 'Mobile Safari',
    'webOS', 'Kindle', 'Silk', 'Fennec', 'Maemo', 'Tablet'
  ];
  
  var lowerUserAgent = userAgent.toLowerCase();
  
  // 检查移动设备关键词
  for (var i = 0; i < mobileKeywords.length; i++) {
    if (lowerUserAgent.includes(mobileKeywords[i].toLowerCase())) {
      return true;
    }
  }
  
  // 检查移动设备正则表达式
  var mobileRegex = /android|webos|iphone|ipad|ipod|blackberry|iemobile|opera mini/i;
  return mobileRegex.test(userAgent);
}

async function handleRequest(request) {
  try {
    var url = new URL(request.url);
    var imgType = url.searchParams.get('img');
    
    if (imgType === 'h') {
      // 生成1到maxHorizontalImageNumber之间的随机数
      var randomNum = Math.floor(Math.random() * CONFIG.maxHorizontalImageNumber) + 1;
      var proxyUrl = 'https://cnb.cool/2x.nz/r3/-/git/raw/main/ri/h/' + randomNum + '.webp';
      
      // 发起反代请求
      var proxyResponse = await fetch(proxyUrl, {
        headers: {
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
          'User-Agent': request.headers.get('User-Agent') || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
      });
      
      if (!proxyResponse.ok) {
        return new Response('❌ 获取图片失败: ' + proxyResponse.status + ' ' + proxyResponse.statusText, {
          status: proxyResponse.status,
          headers: { 'Content-Type': 'text/plain; charset=utf-8' }
        });
      }
      
      // 获取图片数据
      var imageData = await proxyResponse.arrayBuffer();
      
      // 返回图片
      return new Response(imageData, {
        status: 200,
        headers: {
          'Content-Type': 'image/webp',
          'Cache-Control': 'public, max-age=3600',
          'Access-Control-Allow-Origin': '*',
          'X-Image-Number': randomNum.toString(),
          'X-Proxy-Url': proxyUrl
        }
      });
    } else if (imgType === 'v') {
      // 生成1到maxVerticalImageNumber之间的随机数
      var randomNum = Math.floor(Math.random() * CONFIG.maxVerticalImageNumber) + 1;
      var proxyUrl = 'https://cnb.cool/2x.nz/r3/-/git/raw/main/ri/v/' + randomNum + '.webp';
      
      // 发起反代请求
      var proxyResponse = await fetch(proxyUrl, {
        headers: {
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
          'User-Agent': request.headers.get('User-Agent') || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
      });
      
      if (!proxyResponse.ok) {
        return new Response('❌ 获取图片失败: ' + proxyResponse.status + ' ' + proxyResponse.statusText, {
          status: proxyResponse.status,
          headers: { 'Content-Type': 'text/plain; charset=utf-8' }
        });
      }
      
      // 获取图片数据
      var imageData = await proxyResponse.arrayBuffer();
      
      // 返回图片
      return new Response(imageData, {
        status: 200,
        headers: {
          'Content-Type': 'image/webp',
          'Cache-Control': 'public, max-age=3600',
          'Access-Control-Allow-Origin': '*',
          'X-Image-Number': randomNum.toString(),
          'X-Proxy-Url': proxyUrl
        }
      });
    } else if (imgType === 'ua') {
      // 根据User-Agent检测设备类型
      var userAgent = request.headers.get('User-Agent') || '';
      var isMobile = isMobileDevice(userAgent);
      
      if (isMobile) {
        // 移动设备，返回竖屏图片
        var randomNum = Math.floor(Math.random() * CONFIG.maxVerticalImageNumber) + 1;
        var proxyUrl = 'https://cnb.cool/2x.nz/r3/-/git/raw/main/ri/v/' + randomNum + '.webp';
        
        var proxyResponse = await fetch(proxyUrl, {
          headers: {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'User-Agent': request.headers.get('User-Agent') || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
          }
        });
        
        if (!proxyResponse.ok) {
          return new Response('❌ 获取图片失败: ' + proxyResponse.status + ' ' + proxyResponse.statusText, {
            status: proxyResponse.status,
            headers: { 'Content-Type': 'text/plain; charset=utf-8' }
          });
        }
        
        var imageData = await proxyResponse.arrayBuffer();
        
        return new Response(imageData, {
          status: 200,
          headers: {
            'Content-Type': 'image/webp',
            'Cache-Control': 'public, max-age=3600',
            'Access-Control-Allow-Origin': '*',
            'X-Image-Number': randomNum.toString(),
            'X-Proxy-Url': proxyUrl,
            'X-Device-Type': 'mobile'
          }
        });
      } else {
        // 桌面设备，返回横屏图片
        var randomNum = Math.floor(Math.random() * CONFIG.maxHorizontalImageNumber) + 1;
        var proxyUrl = 'https://cnb.cool/2x.nz/r3/-/git/raw/main/ri/h/' + randomNum + '.webp';
        
        var proxyResponse = await fetch(proxyUrl, {
          headers: {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'User-Agent': request.headers.get('User-Agent') || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
          }
        });
        
        if (!proxyResponse.ok) {
          return new Response('❌ 获取图片失败: ' + proxyResponse.status + ' ' + proxyResponse.statusText, {
            status: proxyResponse.status,
            headers: { 'Content-Type': 'text/plain; charset=utf-8' }
          });
        }
        
        var imageData = await proxyResponse.arrayBuffer();
        
        return new Response(imageData, {
          status: 200,
          headers: {
            'Content-Type': 'image/webp',
            'Cache-Control': 'public, max-age=3600',
            'Access-Control-Allow-Origin': '*',
            'X-Image-Number': randomNum.toString(),
            'X-Proxy-Url': proxyUrl,
            'X-Device-Type': 'desktop'
          }
        });
      }
    } else {
      // 显示使用说明
      var helpText = '🖼️ 随机图片展示器\n\n';
      helpText += '使用方法:\n';
      helpText += '• ?img=h - 获取横屏随机图片\n';
      helpText += '• ?img=v - 获取竖屏随机图片\n';
      helpText += '• ?img=ua - 根据设备类型自动选择图片\n\n';
      helpText += '配置信息:\n';
      helpText += '• 横屏图片最大编号: ' + CONFIG.maxHorizontalImageNumber + '\n';
      helpText += '• 竖屏图片最大编号: ' + CONFIG.maxVerticalImageNumber + '\n';
      
      return new Response(helpText, {
        status: 200,
        headers: { 
          'Content-Type': 'text/plain; charset=utf-8',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }

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
