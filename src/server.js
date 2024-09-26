const express = require('express');
const request = require('request');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
app.use(bodyParser.json());

const appID = 'xxxxxxxxxxxxxxxxxx'; // 小程序Id
const appSecret = 'xxxxxxxxxxxxxxxxxx'; // 小程序密钥
const mchId = 'xxxxxxxxxxxxxxxxxx'; // 商户号
const apiKeyV3 = 'xxxxxxxxxxxxxxxxxx'; // v3密钥
const serialNo = 'xxxxxxxxxxxxxxxxxx'; // 商家序列号

// 加载商户私钥
const privateKey = fs.readFileSync('./apiclient_key.pem', 'utf8');
const wechatPublicKey = fs.readFileSync('./wechatpay_public_key.pem', 'utf8'); // 微信支付平台公钥

app.post('/onLogin', (req, res) => {
    const jsCode = req.body.code;
    const url = `https://api.weixin.qq.com/sns/jscode2session?appid=${appID}&secret=${appSecret}&js_code=${jsCode}&grant_type=authorization_code`;
    request(url, (error, response, body) => {
        if (!error && response.statusCode === 200) {
            const data = JSON.parse(body);
            if (data.session_key) {
                res.send({ sessionKey: data.session_key, openid: data.openid, success: 'success' });
            } else {
                res.status(500).send({ success: false, message: 'Failed to get session key' });
            }
        } else {
            res.status(500).send({ success: false, message: 'Error getting session key' });
        }
    });
});

app.post('/getPhoneNumber', (req, res) => {
    const { sessionKey, encryptedData, iv } = req.body;

    if (!sessionKey || !encryptedData || !iv) {
        return res.status(400).send({ success: false, message: 'Missing required parameters' });
    }

    try {
        const decipher = crypto.createDecipheriv('aes-128-cbc', Buffer.from(sessionKey, 'base64'), Buffer.from(iv, 'base64'));
        let decrypted = decipher.update(encryptedData, 'base64', 'utf8');
        decrypted += decipher.final('utf8');

        const phoneInfo = JSON.parse(decrypted);
        res.send({ success: true, phoneNumber: phoneInfo.phoneNumber });
    } catch (err) {
        res.status(500).send({ success: false, message: 'Error decrypting phone number', error: err.message });
    }
});

app.post('/wechat/getOpenid', (req, res) => {
    const jsCode = req.body.code;
    const url = `https://api.weixin.qq.com/sns/jscode2session?appid=${appID}&secret=${appSecret}&js_code=${jsCode}&grant_type=authorization_code`;
    request(url, (error, response, body) => {
        if (!error && response.statusCode === 200) {
            const data = JSON.parse(body);
            if (data.openid) {
                res.send({ openid: data.openid, success: 'success' });
            } else {
                res.status(500).send({ success: false, message: 'Failed to get openId' });
            }
        } else {
            res.status(500).send({ success: false, message: 'Error getting openId' });
        }
    });
});

function generateSignature(data) {
    const sign = crypto.createSign('SHA256');
    sign.update(data);
    sign.end();
    return sign.sign(privateKey, 'base64');
}

async function createOrder(openid, out_trade_no, total_fee) {
    const method = 'POST';
    const urlPath = '/v3/pay/transactions/jsapi';
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const nonceStr = crypto.randomBytes(16).toString('hex');
    const body = JSON.stringify({
        appid: appID,
        mchid: mchId,
        description: 'Test Product',
        out_trade_no: out_trade_no,
        notify_url: 'https://aba3-2408-8417-28e0-bab8-a97c-2b47-584c-6570.ngrok-free.app/notify',
        amount: {
            total: total_fee,
            currency: 'CNY'
        },
        payer: {
            openid: openid
        }
    });

    const dataToSign = `${method}\n${urlPath}\n${timestamp}\n${nonceStr}\n${body}\n`;
    const signature = generateSignature(dataToSign);

    const options = {
        url: 'https://api.mch.weixin.qq.com' + urlPath,
        method: method,
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
            'Authorization': `WECHATPAY2-SHA256-RSA2048 mchid="${mchId}",nonce_str="${nonceStr}",timestamp="${timestamp}",serial_no="${serialNo}",signature="${signature}"`
        },
        body: body
    };

    return new Promise((resolve, reject) => {
        request(options, (error, response, body) => {
            if (error) {
                reject(error);
            } else {
                resolve(JSON.parse(body));
            }
        });
    });
}

/**
 * 生成支付所需的参数。
 * 
 * 该函数用于生成支付所需的各种参数，包括时间戳、随机字符串、包参数及签名。其中最重要的是参数的生成与签名过程，以确保支付信息的安全性和完整性。
 * 
 * @param {string} prepayId - 预支付标识符，用于生成包参数。
 * @returns {Object} - 包含时间戳（timeStamp）、随机字符串（nonceStr）、包参数（packageVal）、签名类型（signType）以及支付签名（paySign）的对象。
 */
function generatePayParams(prepayId) {
    // 生成时间戳，用于确保支付请求的唯一性
    const timestamp = Math.floor(Date.now() / 1000).toString();

    // 生成16字节的随机字符串，用于增加支付请求的安全性
    const nonceStr = crypto.randomBytes(16).toString('hex');

    // 包参数，固定格式，用于传递预支付标识符
    const pkg = `prepay_id=${prepayId}`;

    // 签名类型，暂时固定为RSA，用于数字签名过程
    const signType = 'RSA';

    // 需要进行签名的数据，用于生成支付签名
    const dataToSign = `${appID}\n${timestamp}\n${nonceStr}\n${pkg}\n`;

    // 根据待签名数据生成支付签名
    const paySign = generateSignature(dataToSign);

    // 返回生成的支付参数
    return {
        timeStamp: timestamp,
        nonceStr: nonceStr,
        packageVal: pkg,
        signType: signType,
        paySign: paySign
    };
}

app.post('/wechat/createOrder', async (req, res) => {
    const { openid, total_fee } = req.body;
    try {
        const out_trade_no = generateOutTradeNo();
        const result = await createOrder(openid, out_trade_no, total_fee);

        if (result.prepay_id) {
            const paymentParams = generatePayParams(result.prepay_id);
            res.send(paymentParams);
        } else {
            console.error('Error getting prepay_id:', result);
            res.status(500).send({ error: result.message });
        }
    } catch (error) {
        console.error('Error creating order:', error);
        res.status(500).send({ error: 'Internal server error' });
    }
});

function generateOutTradeNo() {
    return 'your_trade_no_' + Date.now();
}

app.post('/notify', (req, res) => {
    const payload = JSON.stringify(req.body); // 使用 JSON.stringify 将请求体转换为字符串
    const signature = req.headers['wechatpay-signature'];
    const timestamp = req.headers['wechatpay-timestamp'];
    const nonce = req.headers['wechatpay-nonce'];

    // 验证签名
    const verify = crypto.createVerify('SHA256');
    verify.update(`${timestamp}\n${nonce}\n${payload}\n`);

    const isVerified = verify.verify(wechatPublicKey, signature, 'base64');

    if (isVerified) {
        // 签名验证成功，处理支付结果通知
        const notification = JSON.parse(payload);
        console.log('Payment notification:', notification);

        // 根据通知内容处理业务逻辑，例如更新订单状态
        // ...

        // 返回成功应答
        res.status(200).send('success');
    } else {
        // 签名验证失败
        console.error('Signature verification failed');
        res.status(400).send('signature verification failed');
    }
});

const port = 3000;
app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});
