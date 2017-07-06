'use strict'; // enable ES6
var crypto = require('crypto');
var request = require('request');
var fs = require('fs');
var ursa = require('ursa-purejs');
var os = require('os');
var forge = require('node-forge');
var colors = require('colors');
var dateFormat = require('dateformat');
var log = require('./logger.js');

/**
 * Basic virtual IoT device impl for Oracle IoT server using APIv2.
 */
module.exports = class iotDevice {

    constructor(iotServer, deviceId, activationId, sharedSecret, privateKey) {
        this.algorithm = 'RSA';
        this.deviceId = deviceId;
        this.server = iotServer;
        this.beaconInterval = 240;
        this.clientToken = null;
        this.clientTokenExpTime = null;
        this.endpointId = deviceId;
        this.messageQueue = [];
        this.activationId = activationId;
        this.sharedSecret = sharedSecret;
        this.sendSuccessCount = 0;
        this.sendErrorCount = 0;
        setInterval(() => { this._processMessageQueue() }, 500);    
    }

    /**
     * Saves the details of this device to the disk as JSON data file.
     * @param deviceFile
     */
    saveToFile(deviceFile) {
        deviceFile = deviceFile || "./" + this.deviceId + ".json";
        var data = {
            id: this.deviceId,
            hardwareId: this.activationId,
            sharedSecret: this.sharedSecret,
            privateKey: this.getPrivateKey()
        };
        fs.writeFileSync(deviceFile, JSON.stringify(data));
    }

    loadFromFile(deviceFile) {
        var data = JSON.parse(fs.readFileSync(deviceFile, 'utf8'));
        this.deviceId = data.id;
        this.activationId = data.hardwareId;
        this.sharedSecret = data.sharedSecret;
        this.endpointId = data.id;
        try {
            this.loadEncryiptionKeys(data.privateKey);
        } catch(Error) {
            this.generateEncryiptionKeys();
            this.saveToFile(deviceFile);
        }
    }

    /**
     * Loads the private and public key pair for this IoT Device.
     */
    loadEncryiptionKeys(privateKey) {
        if (privateKey) {
            this.privateKey = privateKey;
            this.publicKey = ursa.createPrivateKey(this.privateKey).toPublicPem('base64');
        }
        else {
            generateEncryiptionKeys();
        }
    }

    /**
    * Generate a private and public key pair for this IoT Device.
    */
    generateEncryiptionKeys() {
        log.info('Generating key-pair for ' + this.deviceId);
        var keys = ursa.generatePrivateKey(2048);
        this.privateKey = keys.toPrivatePem('base64');
        this.publicKey = keys.toPublicPem('base64');
    }

    /**
     * Gets the public key for this device.
     * @returns {string} - PEM encoded public key.
     */
    getPublicKey() {
        if (!this.publicKey)
            this.generateEncryiptionKeys();
        return this.publicKey;
    }

    /**
     * Gets the public key for this device.
     * @returns {string} - PEM encoded private key.
     */
    getPrivateKey() {
        if (!this.privateKey)
            this.generateEncryiptionKeys();
        return this.privateKey;
    }

    /**
     * Generates a signature for the specified data.
     * @param {Buffer} data - to generate a signature for
     * @returns {Object} the signature as byte-array
     */
    signWithPrivateKey(data) {
        var md = forge.md.sha256.create();
        md.update(data);
        var pk = forge.pki.privateKeyFromPem(this.getPrivateKey());
        return pk.sign(md);
    }

    /**
     * Generates a SHA256 HMac signature for the specified data using the supplied secret.
     * @param {Buffer} data - data to generate signature for
     * @returns {Object} the signature
     */
    signWithSharedSecret(data) {
        return crypto.createHmac('SHA256', this.sharedSecret).update(data).digest()
    }

    /**
     * Generate a JSON-web-token (JWT) that can be used for authentication.
     * @param {string} iss - Issuer of the JWT token     
     * @param {string} exp - Expirey time of the generated token
     * @param {string} alg - Hash alorthim used to gnereate the signature, can either be HS256 or RS256.
     * @param {string} secret - Secert used for signing the data
     */
    getJwtToken(iss, exp, alg) {
        if (alg != 'HS256' && alg != 'RS256')
            throw new Error("Invalid JWT hash algorithm: " + alg);

        log.info("Create JWT token for: " + iss);
        var header = {
            typ: 'JWT',
            alg: alg
        };
        var payload = {
            iss: iss,
            sub: iss,
            aud: 'oracle/iot/oauth2/token',
            exp: Math.ceil(exp ? exp : (Date.now() / 1000) + 240),
        };

        var jwtPayload = new Buffer(JSON.stringify(header)).toString('base64') + '.' + new Buffer(JSON.stringify(payload)).toString('base64');
        if (alg == 'HS256') {
            var tokenSignature = new Buffer(this.signWithSharedSecret(jwtPayload)).toString('base64');
        } else if (alg == 'RS256') {
            var tokenSignature = forge.util.encode64(this.signWithPrivateKey(jwtPayload));
        }

        var bearerToken = jwtPayload + '.' + tokenSignature;
        bearerToken = bearerToken.replace(/\+/g, '-').replace(/\//g, '_').replace(/\=+$/, '');
        return bearerToken;
    }

    /**
     * Request an access token from the IoT server for communiction purposes.
     * @param {string} jwtToken - the JWT token to use for authentication; use getJwtToken to get a valid JWT token.
     * @param {scope} scope - request scope for the OAuth request
     * @param cb - callback
     */
    requestAccessToken(jwtToken, scope, cb) {
        log.info("Request OAuth access token for: " + (scope ? scope : "{empty}"));
        request.post({
            url: this.server + "/iot/api/v2/oauth2/token",
            json: true,
            headers: { "Accept": "application/json" },
            form: {
                grant_type: 'client_credentials',
                client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                client_assertion: jwtToken,
                scope: scope
            }},
             (err, response, body) => {
                //res(error, body
                log.detail("Access token request reply: " + JSON.stringify(body))
                if (!err) {
                    //var parsedBody = JSON.parse(body);
                    var accessToken = body.access_token;
                    log.info("Access token: " + accessToken);
                    if (cb) cb(null, accessToken);
                }
                else {
                    log.error("No access token in body!")
                    if (cb) cb(err);
                }
            }
        );
    }

    /**
     * Activate the device on the IoT server.
     * @param {array} deviceModels - Device models this device supports.
     * @param cb
     */
    activateDevice(deviceModels, cb) {
        // check if we can activate the device,
        if (!this.activationId && !this.sharedSecret)
            throw new Error("No activation id or activation secert have been set during device creation; unable to send activation request.");

        // public key needs to be stripped from the PEM headers
        var actPublicKey = this.getPublicKey()
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .trim();

        // esnure the device models contains the direct_activation capability
        var directActivationModel = "urn:oracle:iot:dcd:capability:direct_activation";
        if (deviceModels.indexOf(directActivationModel)) {
            deviceModels.push(directActivationModel);
        }

        //var secretHash = crypto.createHmac('SHA256', sharedSecret).update(activationId).digest();
        var signatureString =
            forge.util.bytesToHex(forge.util.encodeUtf8(this.activationId) + '\n' + this.algorithm + '\nX.509\nHmacSHA256\n')
            + forge.util.bytesToHex(this.signWithSharedSecret(this.activationId))
            + forge.util.bytesToHex(forge.util.decode64(actPublicKey));
        var signature =
            forge.util.encode64(
                this.signWithPrivateKey(forge.util.hexToBytes(signatureString)));

        /*var md = forge.md.sha256.create();
        md.update(forge.util.hexToBytes(signatureString));
        var pk = forge.pki.privateKeyFromPem(privateKey);
        var signature = forge.util.encode64(pk.sign(md));*/        
        var activationRequest = {
            "deviceModels": deviceModels,
            "certificationRequestInfo": {
                "subject": this.activationId,
                "subjectPublicKeyInfo": {
                    "algorithm": this.algorithm,
                    "publicKey": actPublicKey,
                    "format": "X.509",
                    "secretHashAlgorithm": "HmacSHA256"
                },
                "attributes": {}
            },
            "signatureAlgorithm": "SHA256withRSA",
            "signature": signature
        }

        this.requestAccessToken(
            this.getJwtToken(this.activationId, null, 'HS256'),
            'oracle/iot/activation',
            (err, accessToken) => {
                //getActivationPolicy(authToken);
                request.post({
                    url: this.server + "/iot/api/v2/activation/direct",
                    json: true,
                    headers: {
                        "content-type": "application/json",
                        "Authorization": "Bearer " + accessToken,
                        "Accept": "application/json",
                        "X-ActivationId": this.activationId
                    },
                    body: activationRequest
                }, function (err, response, body) {
                    log.detail("Activation reply (" + response.statusCode + "): " + JSON.stringify(body));
                    if (!err) {
                        if (cb) cb(null);
                    }
                    else {
                        if (cb) cb(err);
                    }
                }
                );
            });
    }

    /**
     * Gets the activation policy for this device
     * @param jwtToken
     * @param res
     */
    getActivationPolicy(jwtToken, cb) {
        log.info("request getActivationPolicy");
        request.get({
            url: this.server + "/iot/api/v2/activation/policy?OSName=" + os.type() + "&OSVersion=1",
            json: true,
            headers: {
                "content-type": "application/json",
                "Authorization": "Bearer " + jwtToken,
                "X-ActivationId": this.activationId
            }
        }, function (err, response, body) {
            log.info("getActivationPolicy reply (" + response.statusCode + "): " + JSON.stringify(body))
            if (response.statusCode == 200) {
                if (cb) cb(null, body);
            }
            else {
                if (cb) cb(err, null);
            }
        });
    }

    _processMessageQueue() {
        while (this.messageQueue.length > 0) {
            // we are requesting an access token; wait till we have a valid token befoe sending a message
            if (this.requestingAccessToken)
                return;                   
            // check for token
            if (!this.clientToken || this.clientTokenExpTime < Date.now()) {
                log.detail("No or expired beacon token found; request new token from server");
                this._requestClientToken();
            } else {
                // get message from top of the queue
                var message = this.messageQueue.shift();
                log.detail("Dequeue message and try sending it (attempt " + (++message.sendCount) + ")");
                 // valid token found; send message
                this._sendMessage(message.payload, this.clientToken, (err) => {
                    // returned failed message to the queue
                    if (err) {
                        if (message.sendCount > 3) {
                            log.error("Failed to send message after; giving up after " + +message.sendCount + " attempts");
                            message.callback(err);
                        } else {
                            log.error("Failed to send message; returning to queue for reporcessing");
                            this.messageQueue.unshift(message);
                        }
                    }
                    else {
                        message.callback(null);
                    }
                });
            }
        }
    }

    _requestClientToken() {
        if (this.requestingAccessToken)
            return;
        // no (or expired) access token; request a new one
        this.requestingAccessToken = true;
        var newExpTime = Date.now() + this.beaconInterval * 1000;
        this.requestAccessToken(
            this.getJwtToken(this.deviceId, (newExpTime / 1000), 'RS256'),
            '',
            (err, authToken) => {
                if (err) {
                    log.error("Unable to obtain new client assertion token; device disabled or registration expired?");
                } else {
                    this.clientToken = authToken;
                    this.clientTokenExpTime = newExpTime - 1000;
                }
                this.requestingAccessToken = false;
            });
    }

    _sendMessage(message, accessToken, cb) {      
        request.post({
            url: this.server + "/iot/api/v2/messages",
            json: true,
            headers: {
                "content-type": "application/json",
                "Authorization": "Bearer " + this.clientToken,
                "X-EndpointId": this.endpointId
            },
            body: message
        }, (err, response, body) => {
            log.detail("Send message reply: " + JSON.stringify(body))
            if (response.statusCode == 202) {
                this.sendSuccessCount++;
                log.info("Message accepted by server (" + response.statusCode + ")");
                if (cb) cb(null, body);
            }
            else {
                this.sendErrorCount++;
                log.error("Message refused by server (" + response.statusCode + ")");
                if (cb) cb(err, null);
            }
        });
    }

    /**
     * Send an message from this IoT device to the IoT server.
     * @param {string} format - Message format to for the message.
     * @param {object} data - JSON payload
     * @param {object} cb - callback invoked when the message is send
     */
    sendMessage(format, data, cb) {
        log.info("Queuing IoT message: " + JSON.stringify(data));
        var message = [
            {
                "clientId": crypto.randomBytes(16).toString('hex'),
                "source": this.endpointId,
                "destination": "",
                "priority": "LOW",
                "reliability": "BEST_EFFORT",
                "eventTime": new Date().getTime() - 10 * 1000,
                "sender": "",
                "type": "DATA",
                "properties": {
                },
                "payload": {
                    "format": format + ":attributes",
                    "data": data
                }
            }
        ];        
        this.messageQueue.push({ payload: message, callback: cb, sendCount: 0 });
    }
}

