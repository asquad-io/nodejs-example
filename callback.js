const http = require('http');
const sha256 = require('crypto-js/sha256');
const hmacSHA256 = require('crypto-js/hmac-sha256');
const base64 = require('crypto-js/enc-base64');

// Api keys
const apiKey = process.env.API_KEY;
const apiSecret = process.env.API_SECRET;

// Server properties
const hostname = '127.0.0.1';
const port = 8004;

const server = http.createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');

    if (req.method === 'POST') {
        let body = '';
        req.on('data', function (chunk) {
            body += chunk.toString();
        });
        req.on('end', function () {
            console.log('Received callback: ', body);
            console.log('Headers: ', req.headers);

            try {
                // Get hash of body using SHA256 algo and encode it the result with Base64.
                const digest = 'SHA-256=' + base64.stringify(sha256(body));

                if (req.headers['digest'] !== digest) {
                    throw Error('Invalid digest. Expected ' + digest + ' got ' + req.headers['digest']);
                }

                // Preparing signature params
                let signatureParams = {};
                req.headers['signature'].split(", ").forEach(item => {
                    const n = item.indexOf("=");
                    const key = item.substring(0, n);
                    const value = item.substring(n + 2, item.length - 1)
                    signatureParams[key] = value;
                });

                // Check api key
                if (signatureParams['keyId'] !== apiKey) {
                    throw Error('Invalid api key');
                }

                // Obtaining signed headers
                const signedHeaders = signatureParams['headers'];
                if (!signedHeaders) {
                    throw Error('Undefined authorization param `headers`');
                }

                // Preparing signature payload
                let signaturePayload = '';
                signatureParams['headers'].split(" ").forEach(item => {
                    const header = req.headers[item.toLowerCase()];
                    if (!header) {
                        throw Error('Undefined header ' + item);
                    }
                    signaturePayload += item + ': ' + header;
                })

                // Creating signature using HMAC-SHA256 and encode it the result with Base64.
                const signature = base64.stringify(hmacSHA256(signaturePayload, apiSecret));

                if (signature !== signatureParams['signature']) {
                    throw Error('Invalid signature');
                }

                console.log('Signature verified')

                res.writeHead(200);
                res.end();

                const callback = JSON.parse(body);

                console.log('Received callback id: ', callback.identifier);

                const errorCode = callback.error_code;

                if (errorCode !== 0) {
                    console.log('Transaction failed with status `' + callback.status + '` and code `' + errorCode + '`');
                } else {
                    const status = callback.status;

                    switch (status) {
                        case 'success':
                            console.log('Transaction completed successfully');
                            break;
                        default:
                            console.log('Transaction failed with status ', status);
                    }
                }
            } catch (e) {
                console.log('error: ', e);
                res.writeHead(500);
                res.end();
            }
        });
    } else {
        res.writeHead(500);
        res.end();
    }
});

server.listen(port, hostname, () => {
    console.log(`Server running at http://${hostname}:${port}/`);
});