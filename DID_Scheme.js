const fs = require('fs')
const path = require('path')
const cors = require('cors')
const express = require('express')
const app = express()
const port = 6666

const bodyParser = require('body-parser');
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
    extended: true
}));

// Identity Overlay Network (ION) 
const ION = require('@decentralized-identity/ion-tools')

var claimsSeparator = ","
var contextCredPath = './information_vault/'
var currentDate = new Date().valueOf()
var userIdentityPath = './information_vault/user.json'
var contextCredSuffix = "-contextCred.json"
var masterCredPath = './information_vault/masterCred.json'
var issuerIdentityPath = './information_vault/issuer.json'
var userSigningKeyPath = './information_vault/userSign.json'

// Enable CORS
app.use(cors());

// for singing keys
let elliptic = require('elliptic')
let sha3 = require('js-sha3');
let ec = new elliptic.ec('secp256k1');

function hashOfString(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        let character = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + character;
        hash &=  hash; // convert to 32-bit integer
    }
    return new Uint32Array([hash])[0].toString(36);
}

function hashOfArray(strArray) {
    if (strArray == null) {
        return null;
    } else if (strArray.length == 1) {
        return hashOfString(strArray[0]);
    } else {
        let temp = strArray[0];
        for (let i = 1; i < strArray.length; i++) {
            temp = temp.concat(strArray[i]);
        }
        return hashOfString(temp);
    }
}

// Asynchronously store issuer's or user's identity
function storeIdentityInInformationVault(data, role) {
    let identityPath = '';
    switch (role) {
        case 'issuer':
            identityPath = issuerIdentityPath;
            break;
        case 'userDID':
            identityPath = userIdentityPath;
            break;
        default:
            identityPath = userSigningKeyPath;
            break;
    }
    fs.writeFile(identityPath, data, (err) => {
        if (err) {
            throw err;
        }
        console.log(`>> Generate ${role} identity successfully!`);
    });
}

// Load issuer identity
function loadIssuerIdentity() {
    let data = fs.readFileSync(issuerIdentityPath, 'utf-8');
    console.log(">> Load issuer's identity successfully!");
    console.log(JSON.parse(data).keyPair.publicJwk);
    return data;
}

// Load user identity
function loadUserIdentity() {
    let data = fs.readFileSync(userIdentityPath, 'utf-8');
    console.log(">> Load user identity successfully!");
    return data;
}

// Load user signing keys
function loadUserSigningKey() {
    let data = fs.readFileSync(userSigningKeyPath, 'utf-8');
    console.log(">> Load user's signing key successfully!");
    return data;
}

function signJws(payloadParam) {
    let issuer = loadIssuerIdentity();
    let issuerJson = JSON.parse(issuer);
    console.log(issuerJson.keyPair.privateJwk);
    if (issuer = null) {
        console.log(">> Issuer identity is null!");
        return;
    } else {
        return ION.signJws({
            payload: payloadParam,
            privateJwk: issuerJson.keyPair.privateJwk
        });
    }
}

function verifyJws(jwsParam) {
    let issuer = loadIssuerIdentity();
    let issuerJson = JSON.parse(issuer);
    console.log(issuerJson.keyPair.publicJwk);
    if (issuer = null) {
        console.log(">> Issuer identity is null!");
        return;
    } else {
         return ION.verifyJws({
            jws: jwsParam,
            privateJwk: issuerJson.keyPair.privateJwk
        });
    }
}

// Generate the basic DID information under the ION PKI-like architecture
async function generateDID() {
    // Asynchronous invoke the ION API to generate 'secp256k1' key pair
    let keyPair = await ION.generateKeyPair('secp256k1');
    let did = new ION.DID({
        content: {
            publicKeys: [
                {
                    id: 'key-1',
                    type: 'EcdsaSecp256k1VerificationKey2019',
                    publicKeyJwk: keyPair.publicJwk,
                    purposes: [ 'authentication' ]
                }
            ],
            services: [
                {
                    id: 'did-example-1',
                    type: 'LinkedDomains',
                    serviceEndpoint: 'https://xxx.com'
                }
            ]
        }
    });
    let longFormURI = await did.getURI();
    let shortFormURI = await did.getURI('short');
    console.log(">> Generate decentralized identifier (DID): ", shortFormURI);
    return JSON.stringify({
        did: shortFormURI,
        didLongForm: longFormURI,
        keyPair: keyPair
    })
}

// Generate the secp256k1 key pair for digital signing
// The user's private Jwk should be be used for signing
// For the example, we generate another pair of keys for signing
app.get('/did/v0/getUserSigningKeys', (req, res) => {
    if (fs.existsSync(userSigningKeyPath)) {
        console.log(">> User signing key has been initialized, reading from local information vault...");
        // read from local information vault
        let data = loadUserSigningKey();
        res.json(JSON.parse(data));
    } else {
        // generate secp256k1 keys
        let keyPair = ec.keyFromPrivate("86ddae0f3a25b92168165412149d65d6289b9cefaf17da2c378e25cdc45a3c2e");
        let privKey = keyPair.getPrivate("hex");
        let pubKey = keyPair.getPublic();
        let userSignKeys = JSON.stringify({
            type: 'secp256k1',
            privKey: privKey,
            pubKey: pubKey
        })
        storeIdentityInInformationVault(userSignKeys, 'userSignKey');
        res.json(JSON.parse(userSignKeys));
    }
})

// Sign using secp256k1 private key
app.get('/did/v0/digitalSign', (req, res) => {
    let msg = req.query.message;
    let msgHash = sha3.keccak256(msg);

    let keyPair = loadUserSigningKey();
    let keyPairJSON = JSON.parse(keyPair);
    console.log('>> keyPairJSON: ', keyPairJSON);

    let signature = ec.sign(msgHash, keyPairJSON.privKey, "hex", {canonical: true});
    console.log(`>> Msg: ${msg}`);
    console.log(`>> Msg hash: ${msgHash}`);
    console.log(">> Sig:", signature);
    res.send(JSON.parse(JSON.stringify({
        success: true,
        signature: signature
    })));
})

// Verify the digital signature
app.post('/did/v0/digitalVerify', (req, res) => {
    let msg = req.query.message;
    let msgHash = sha3.keccak256(msg);
    let inputSig = req.body;
    let signature = JSON.parse(JSON.stringify(inputSig));
    let hexToDecimal = (x) => ec.keyFromPrivate(x, "hex").getPrivate().toString(10);
    let pubKeyRecovered = ec.recoverPubKey(hexToDecimal(msgHash), signature, signature.recoveryParam, "hex");
    let validSig = ec.verify(msgHash, signature, pubKeyRecovered);
    res.send(JSON.parse(JSON.stringify({
        success: true,
        result: validSig
    })))
})


// Initialize the key pair for the issuer committee
app.get('/did/v0/initializeIssuer', (req, res) => {
    if (fs.existsSync(issuerIdentityPath)) {
        console.log(">> Issuer has been initialized, reading from local information vault...");
        // Read from local information vault
        let data = loadIssuerIdentity();
        res.json(JSON.parse(data).keyPair.publicJwk);
    } else {
        generateDID().then(didData => {
            // Locally store issuer identity
            storeIdentityInInformationVault(didData, 'issuer');
            // Only return publicJwk in issuerKeyPair
            res.json(JSON.parse(didData).keyPair.publicJwk);
        });
    }
})

// Generate a did key pair for a user
app.get('/did/v0/getUserDID', (req, res) => {
    // res.header("Access-Control-Allow-Origin", "*");
    if (fs.existsSync(userIdentityPath)) {
        console.log(">> User identity has been initialized, reading from local information vault...");
        // Read from local information vault
        let data = loadUserIdentity();
        res.send(JSON.parse(data));
    } else {
        generateDID().then((didData) => {
            storeIdentityInInformationVault(didData, 'userDID');
            res.send(JSON.parse(didData));
        })
    }
})

// Asynchronously store credential
function storeCredInInformationVault(masterPath, masterCred) {
    let data = JSON.stringify(masterCred);
    fs.writeFileSync(masterPath, data, (err) => {
        if (err) {
            throw err;
        }
        console.log(">> Locally store credential successfully in information vault!");
    });
}

// Load credential
function loadCred(masterPath) {
    let data = fs.readFileSync(masterPath, 'utf-8');
    console.log(">> Load credential successfully!");
    return data;
}

// The DID Document Object (DDO) contains DID and meta data
app.get('/did/v0/masterCred', async (req, res) => {
    try {
        if (fs.existsSync(masterCredPath)) {
            console.log(">> Master Credential has been issued, reading from local information vault...");
            // Read from local information vault
            let data = loadCred(masterCredPath);
            res.send(JSON.parse(data));
        } else {
            let issuer = loadIssuerIdentity();
            let issuerJson = JSON.parse(issuer);
            let param = [];
            param.push(req.query.name);
            param.push(req.query.ssn);
            param.push(req.query.did);
            let paramHash = hashOfArray(param);
            // The issuer would verify the (zero-knowledge) proof of the claims (i.e., name and ssn in this case) in the master credential before sign it 
            // Besides, the issuer committee follows, e.g., threashold signature, to sign it in future extension
            // Here in the example, we directly sign the user's did using the issuer's secret key
            // The master credential scheme can further be extracted
            signJws(paramHash).then((issuerSignature) => {
                let masterCred = {
                    "issuer": issuerJson.did,
                    "context": "master",
                    "didDocument": {
                        "id": req.query.did,
                        "claims": [
                            {
                                "claimKey": "name",
                                "claimValue": req.query.name,
                                "provider": "SSA"
                            },
                            {
                                "claimKey": "ssn",
                                "claimValue": req.query.ssn,
                                "provider": "SSA"
                            }
                        ],
                        "verificationMethod": [
                            {
                                "id": issuerJson.did,
                                "controller": issuerJson.did,
                                "type": "EcdsaSecp256k1VerificationKey2019",
                                publicKeyJwk: {
                                    "crv": "secp256k1",
                                    "kty": "EC",
                                    "x": issuerJson.keyPair.publicJwk.x,
                                    "y": issuerJson.keyPair.publicJwk.y
                                }
                            }
                        ],
                        "authentication": [
                            req.query.did
                        ]
                    },
                    "issuerCommitteeSignature": {
                        "issuerJwk": issuerSignature
                    },
                    "didDocumentMetadata": {
                        "published": false, // Whether it is stored on chain and DSNs or not
                        "createdTimestamp": currentDate,
                        "expireTimestamp": currentDate + 366*24*60*60*1000 // 1 year before expiring
                    }
                };
                storeCredInInformationVault(masterCredPath, masterCred);
                res.send(masterCred);
            });
        }
    } catch (err) {
        console.log(err);
    }
})

// Verify the master credential
app.get('/did/v0/verifyMasterCred', async (req, res) => {
    let param = [];
    param.push(req.query.name);
    param.push(req.query.ssn);
    param.push(req.query.did);
    let paramHash = hashOfArray(param);
    verifyJws(req.query.issuerSignature, paramHash).then((verificationRes) => {
        let verificationResult = {
            "verificationResult": verificationRes,
            "timestamp": currentDate
        };
        res.send(verificationResult);
    });
})


// Apply for context-based verifiable credentials (layer II) 
app.get('/did/v0/contextCred', (req, res) => {
    try {
        let contextPath = path.resolve(contextCredPath + req.query.specificContext + contextCredSuffix);
        if (fs.existsSync(contextPath)) {
            console.log(">> The credential for such a context has been issued, load from information vault...");
            let data = loadCred(contextPath);
            res.send(JSON.parse(data));
        } else {
            // The credential for such a context has not been issued
            let issuer = loadIssuerIdentity();
            let issuerJson = JSON.parse(issuer);
            let claims = req.query.contextClaims;
            // The claims are seperated by ","
            let claimsArray = claims.split(claimsSeparator);
            // Ensure the claims are in correct format, i.e., (key, value, provider) tuple
            if (claimsArray.length % 3 != 0) {
                throw ">> Incorrect format of the submitted claims for applying for context-based credential!";
            }

            let param = [];
            param.push(req.query.name);
            param.push(req.query.ssn);
            param.push(req.query.masterDID);
            let paramHash = hashOfArray(param);
            // For context-based credential, the committee signs (masterDIDURL, context, {claims})
            verifyJws(req.query.masterIssuerSignature, paramHash).then((verificationRes) => {
                // Verify the master credential when planning to sign and issue context-based credential
                if (verificationRes) {
                    // The claims should attach the (zk) proof, and we omit the verification of this step for example
                    // Besides, we assume the user uses the same public key (as the master credential) for the context-based credential 
                    // to mitigate the linkability, a different public key can be applied in production
                    let contextParams = [];
                    contextParams.push(req.query.masterDID);
                    contextParams.push(req.query.specificContext);
                    contextParams.push(claims);
                    let contextCredHash = hashOfArray(contextParams);
                    // The committee signs the context-based credential
                    signJws(contextCredHash).then(contextIssuerSignature => {
                        // Construct the context-based credential and issue it to the signer
                        let contextCredTemp = {
                            "issuer": issuerJson.did,
                            "context": req.query.specificContext,
                            "didDocument": {
                                "id": req.query.masterDID,
                                "verificationMethod": [
                                    {
                                        "id": issuerJson.did,
                                        "controller": issuerJson.did,
                                        "type": "EcdsaSecp256k1VerificationKey2019",
                                        publicKeyJwk: {
                                            "crv": "secp256k1",
                                            "kty": "EC",
                                            "x": issuerJson.keyPair.publicJwk.x,
                                            "y": issuerJson.keyPair.publicJwk.y
                                        }
                                    }
                                ]
                            },
                            "issuerCommitteeSignature": {
                                "issuerJwk": contextIssuerSignature
                            },
                            "didDocumentMetadata": {
                                "published": false, // Whether it is stored on blockchain and DSNs or not
                                "createdTimestamp": currentDate,
                                "expireTimestamp": currentDate + 20*24*60*60*1000 // 20 days before expiring
                            }
                        };
                        // Construct context-based credential claims json
                        let contextCredClaimsJson = [];
                        for (let i = 0; i < claimsArray.length / 3 ; i++) {
                            let item = {}
                            item['claimKey'] = claimsArray[i*3];
                            item['claimValue'] = claimsArray[i*3+1];
                            item['provider'] = claimsArray[i*3+2]
                            contextCredClaimsJson.push(item);
                        }
                        contextCredTemp['didDocument']['claims'] = contextCredClaimsJson;
                        storeCredInInformationVault(contextPath, contextCredTemp);
                        res.send(contextCredTemp);
                    });
                } else {
                    throw ">> Incorrect verification of master credential!"
                }
            });
        }
    } catch (err) {
        console.log(err);
    }
})

// Verify the context-based credential
app.get('/did/v0/verifyContextCred', async (req, res) => {
    let param = [];
    param.push(req.query.masterDID);
    param.push(req.query.specificContext);
    param.push(req.query.contextClaims);
    let contextCredHash = hashOfArray(param);
    verifyJws(req.query.contextIssuerSignature, contextCredHash).then((verificationRes) => {
        let verificationResult = {
            "verificationResult": verificationRes,
            "timestamp": currentDate
        };
        res.send(verificationResult);
    });
})

// Start the DID service
app.listen(port, () => {
    console.log(`DID Service listens at http://localhost:${port}`)
})