'use strict'; // enable ES6
var crypto = require('crypto');
var request = require('request');
var fs = require('fs');
var ursa = require('ursa-purejs');
var os = require('os');
var forge = require('node-forge');
var colors = require('colors');
var dateFormat = require('dateformat');
var iotDevice = require('./iotdevice.js');
var log = require('./logger.js');

/**
 * Interaction with the oracle IoT CS APIv2
 */
module.exports = class iotcs {

    constructor(server, auth, password) {
        this.server = server;
        if (password) {
            this.authHeader = "Basic " + new Buffer(auth + ":" + password).toString('base64');
        } else {
            this.authHeader = "Basic " + auth;
        }
    }

    _randomUuid() {
        var uuid =
            crypto.randomBytes(2).toString('hex') + ":" +
            crypto.randomBytes(2).toString('hex') + ":" +
            crypto.randomBytes(2).toString('hex') + ":" +
            crypto.randomBytes(2).toString('hex');
        return uuid;
    }

    /**
     * Callback of the createDevice method.
     * @callback createDeviceCallback
     * @param {Object} error
     * @param {iotDevice} iotDevice
     */

    /**
     * Create a new IoT device on the IoT CS server. 
     * @param {string} name - name of the to be create IoT device
     * @param {createDeviceCallback} cb - callback
     */
    createDevice(name, cb) {
        // Create device
        var createRequest = {
            name: name,
            description: "Virtual IoT device",
            metadata: { classification: "Virtual" },
            location: {
                altitude: null,
                latitude: null,
                longitude: null
            },
            manufacturer: "N/A",
            modelNumber: "Virtual IoT Device",
            serialNumber: this._randomUuid(),
            hardwareId: "virt:" + this._randomUuid()
        };

        // make request
        log.info("Request create new IoT device");
        request.post({
            url: this.server + "/iot/api/v2/devices/",
            json: true,
            headers: {
                "content-type": "application/json",
                "Authorization": this.authHeader
            },
            body: createRequest
        }, (err, response, body) => {            
            if (response.statusCode == 201) {
                log.detail("Succesfully created new IoT device with id '" + body.id + "' on server");                
                var sharedSecert = forge.util.decode64(body.sharedSecret);
                var device = new iotDevice(this.server,
                    body.id, body.hardwareId, sharedSecert);
                if (cb) cb(null, device);
            }
            else {
                log.error("Failed to create new IoT device (" + response.statusCode + "): " + JSON.stringify(body));
                if (cb) cb(body, null);
            }
        });
    }

    getDeviceModels(offset, count, cb) {
        log.info("Request available device models from server");
        request.get({
            url: this.server + "/iot/api/v2/deviceModels?limit=" + count ? count : "100",
            json: true,
            headers: {
                "content-type": "application/json",
                "Authorization": this.authHeader
            }
        }, function (err, response, body) {
            log.detail("Response getDeviceModels; statusCode = " + response.statusCode);
            if (response.statusCode == 200) {
                if (cb) cb(null, body);
            }
            else {
                if (cb) cb(err, null);
            }
        });
    }
}
