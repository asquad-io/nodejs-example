const request = require('request');
const sha256 = require('crypto-js/sha256');
const hmacSHA256 = require('crypto-js/hmac-sha256');
const base64 = require('crypto-js/enc-base64');

// Api keys
const apiKey = process.env.API_KEY;
const apiSecret = process.env.API_SECRET;
const host = 'h2h.asquad.dev';

// Preparing request body
const body = JSON.stringify({
    "method": "card",
    "mode": "initial",
    "reference": "nodejs-test-" + Date.now().valueOf(),
    "currency": "XTS",
    "amount": 10.10,
    "customer": {
        "identifier": "test@nodejs.com"
    },
    "card": {
        "pan": "4242424242424242", // success
        // "pan": "4012000000003119", // pending - challenge
        // "pan": "4242424242420000", // decline
        "holder_name": "Holder Name",
        "cvv": "125",
        "exp_month": "10",
        "exp_year": "2035"
    }
})

// Get hash of body using SHA256 algo and encode it the result with Base64.
const digest = 'SHA-256='+base64.stringify(sha256(body));

console.log('digest', digest);

// Preparing signature payload
const signaturePayload = 'host: ' + host + 'digest: ' + digest + 'content-length: ' + body.length;

console.log('signaturePayload', signaturePayload);

// Creating signature using HMAC-SHA256 and encode it the result with Base64.
const signature = base64.stringify(hmacSHA256(signaturePayload, apiSecret));

// Preparing authorization
const authorization = 'Signature keyId="' + apiKey + '", algorithm="HmacSHA256", headers="host digest content-length", signature="' + signature + '"';

console.log("authorization", authorization);

request({
    'method': 'POST',
    'url': (!process.env.OVERRIDE_ADDR ? 'https://' + host  : process.env.OVERRIDE_ADDR) + '/v1/payment',
    'headers': {
        'Content-Type': 'application/json',
        'Authorization': authorization,
        'Digest': digest,
        'Host': host
    },
    body: body
}, function (error, response, body) {
    if (error) {
        console.log('error: ', error);
    } else {
        console.log('statusCode: ', response && response.statusCode);
        console.log('body:', body);

        const statusCode = response.statusCode;

        if (statusCode !== 200) {
            throw Error('Invalid request - ' + statusCode);
        }

        const result = JSON.parse(body);

        console.log('Created transaction with id: ', result.identifier);

        const errorCode = result.error_code;

        if (errorCode !== 0) {
            throw Error('Transaction failed with status `' + result.status + '` and code `' + errorCode + '`');
        }

        const status = result.status;

        switch (status) {
            case 'success':
                console.log('Transaction completed successfully');
                break;
            case 'pending':
                console.log('Need challenge for customer');
                // TODO challenge
                break;
            default:
                console.log('Transaction failed with status ', status);
        }
    }
});
