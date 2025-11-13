const express = require('express');
const axios = require('axios');
const moment = require('moment');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const CryptoJS = require('crypto-js');
const cors = require('cors');
const app = express();
const PORT = 3000;
app.use(cors());

app.use(express.json());

// --- KONSTANTA UTAMA KLIKOO API ---
const BASE_URL = 'pvpapi.stage.pvg.im/klikoo-b2b';

const AUTH_SIGNATURE_ENDPOINT = `https://${BASE_URL}/v1/open-api/auth-signature`;
const ACCESS_TOKEN_ENDPOINT = `https://${BASE_URL}/v1/open-api/access-token`;
const BALANCE_ENDPOINT = `https://${BASE_URL}/v1/open-api/balance`;
const ATTRACTIONS_DETAIL_ENDPOINT = `https://${BASE_URL}/v1/open-api/attractions/detail`;
const BOARDING_LOCATION_ENDPOINT = `https://${BASE_URL}/v1/open-api/transports/sources`;
const DESTINATION_LOCATION_ENDPOINT = `https://${BASE_URL}/v1/open-api/transports/destinations`;


// Kredensial Anda
const CLIENT_ID = '8670d916-9d10-45b9-a091-82b9dedd9b53';
const CLIENT_SECRET = 'vylmiqtm91jq74ct537pdw5vqq05retj';
const PRIVATE_KEY_FILE = 'privatekey.pem';

const PRODUCT_CODE_ATTRACTION = "ATRAKSI-DANCER";
const METHOD_POST = 'POST';
const METHOD_GET = 'GET';
// ------------------------------------

// ------------------------------------------------------------------
// --- FUNGSI UTILITY: MENGHITUNG DIGITAL SIGNATURE (HMAC-SHA512) ---
// ------------------------------------------------------------------
function generateDigitalSignature(method, path, token, payload, timestamp) {

    let stringToHash;

    if (method === METHOD_GET && Object.keys(payload).length === 0) {
        stringToHash = "";
        console.log(`[SIG-DEBUG] Payload untuk Hashing (GET Kosong): ""`);
    } else {
        // ✅ PERBAIKAN KRUSIAL: Gunakan JSON.stringify() dan andalkan urutan key 
        // yang dibuat di handler (product_code, lalu keyword), karena stableStringify gagal.
        stringToHash = JSON.stringify(payload);
        console.log(`[SIG-DEBUG] JSON.stringify Payload (Expected Order: {"product_code":"BUS","keyword":"bandung"}): ${stringToHash}`);
    }

    // 2. hashed_payload = hexEncode(sha256(stringToHash))
    const hashedPayload = CryptoJS.SHA256(stringToHash).toString(CryptoJS.enc.Hex);

    // 3. Bentuk string_to_sign
    const stringToSign = `${method}:${path}:${token}:${hashedPayload}:${timestamp}`;

    console.log(`[SIG-DIGITAL] String To Sign: ${stringToSign}`);
    console.log(`[SIG-DIGITAL] Hashed Payload: ${hashedPayload}`);

    // 4. Hitung HMAC-SHA512
    const cleanSecret = CLIENT_SECRET.trim();
    const hmac = crypto.createHmac('sha512', cleanSecret, 'utf8');
    hmac.update(stringToSign);
    const signatureBase64 = hmac.digest('base64');

    return signatureBase64;
}

// ----------------------------------------------------------------------------------------
// --- FUNGSI UTILITY: MENDAPATKAN AUTH SIGNATURE (LANGKAH 1 & 2) ---
// ----------------------------------------------------------------------------------------

async function getAuthSignature() {
    let privateKeyBase64;
    try {
        const privateKeyContent = fs.readFileSync(path.join(__dirname, PRIVATE_KEY_FILE), 'utf-8');
        privateKeyBase64 = Buffer.from(privateKeyContent).toString('base64').replace(/\n/g, '');
    } catch (err) {
        throw new Error(`Gagal membaca Private Key: ${err.message}. Pastikan file ${PRIVATE_KEY_FILE} ada.`);
    }

    // Timestamp Langkah 1 & 2 tetap menggunakan format panjang (.000)
    const timestamp = moment().format('YYYY-MM-DDTHH:mm:ss.000+07:00');

    const requestBody = { client_id: CLIENT_ID, timestamp: timestamp, private_key: privateKeyBase64 };
    const options = {
        method: 'POST', url: AUTH_SIGNATURE_ENDPOINT,
        headers: { 'Content-Type': 'application/json', 'Open-Api-Timestamp': timestamp },
        data: requestBody
    };

    try {
        const response = await axios(options);
        const signature = response.data.signature || response.data.auth_signature || response.data.data?.signature;
        if (!signature) {
            console.error("[AUTH SIG] Respon sukses, tapi 'signature' tidak ditemukan:", response.data);
            throw new Error("Properti 'signature' tidak ditemukan di response API Auth Signature.");
        }
        console.log(`[AUTH SIG] Auth Signature berhasil didapat.`);
        return { signature: signature, timestamp: timestamp };

    } catch (error) {
        if (error.response) {
            const errMsg = error.response.data.response_message || error.response.statusText;
            console.error(`[AUTH SIG] GAGAL DENGAN STATUS ${error.response.status}:`, error.response.data);
            throw new Error(`Auth Signature Gagal (${error.response.status}): ${errMsg}`);
        }
        throw new Error(`Gagal API Auth Signature: ${error.message}`);
    }
}

async function getAccessToken() {
    let authData;
    try {
        authData = await getAuthSignature();
    } catch (error) {
        throw new Error(`Kesalahan pra-autentikasi (Auth Signature): ${error.message}`);
    }

    const cleanSecret = CLIENT_SECRET.trim();

    const requestBody = {
        grant_type: "client_credentials",
        additional_info: { client_id: CLIENT_ID, client_secret: cleanSecret }
    };

    const headers = {
        'Content-Type': 'application/json',
        'Open-Api-Timestamp': authData.timestamp,
        'Open-Api-Signature': authData.signature
    };

    const options = {
        method: 'POST', url: ACCESS_TOKEN_ENDPOINT,
        headers: headers, data: requestBody
    };

    try {
        console.log("[TOKEN] Memanggil API Access Token...");
        const response = await axios(options);

        const accessToken = response.data.access_token || response.data.data?.access_token;
        if (!accessToken) {
            console.error("[TOKEN] GAGAL: 'access_token' tidak ditemukan. Respons Penuh:", response.data);
            throw new Error("Properti 'access_token' tidak ditemukan di response API Access Token.");
        }

        console.log("[TOKEN] Access Token berhasil diterima.");
        return accessToken;
    } catch (error) {
        if (error.response) {
            const errMsg = error.response.data.response_message || error.response.statusText || 'Kesalahan dari API Token';
            console.error(`[TOKEN] GAGAL DENGAN STATUS ${error.response.status}. Pesan API: ${errMsg}`);
            throw new Error(`Error saat memanggil API Access Token (${error.response.status}): ${errMsg}`);
        }
        throw new Error(`Gagal API Access Token: ${error.message}`);
    }
}


// ----------------------------------------------------------------------------------------
// --- FUNGSI UTILITY: HANDLER UMUM UNTUK API YANG MEMBUTUHKAN DIGITAL SIGNATURE ---
// ----------------------------------------------------------------------------------------
async function callSignedApi(apiType, endpointURL, endpointPath, method, requestBody, res) {
    let accessToken;
    try {
        accessToken = await getAccessToken();
    } catch (error) {
        return res.status(500).json({
            message: `Gagal mendapatkan ${apiType} karena masalah Access Token.`,
            details: error.message
        });
    }

    const token = accessToken;

    // Timestamp Langkah 3 harus Panjang (.000)
    const unifiedTimestampLangkah3 = moment().format('YYYY-MM-DDTHH:mm:ss.000+07:00');
    const timestampSig = unifiedTimestampLangkah3;
    const timestampHeader = unifiedTimestampLangkah3;

    const signaturePayload = (method === METHOD_GET) ? {} : requestBody;

    let digitalSignature;
    try {
        // Hashing akan menggunakan JSON.stringify, menjaga urutan product_code lalu keyword
        digitalSignature = generateDigitalSignature(method, endpointPath, token, signaturePayload, timestampSig);
    } catch (error) {
        console.error(`Kesalahan menghitung Digital Signature untuk ${apiType}:`, error.message);
        return res.status(500).json({
            message: 'Gagal menghitung Digital Signature.',
            details: error.message
        });
    }

    const headers = {
        'Content-Type': 'application/json',
        'Open-Api-Timestamp': timestampHeader,
        'Open-Api-Signature': digitalSignature,
        'Authorization': `Bearer ${accessToken}`
    };

    const options = {
        method: method,
        url: endpointURL,
        headers: headers,
        ...(method === METHOD_POST && { data: requestBody })
    };

    console.log(`[${apiType}] Request Headers:`, headers);
    // Logging request body yang benar (sesuai yang dikirim ke API)
    console.log(`[${apiType}] Request Body Sent: ${JSON.stringify(requestBody)}`);


    try {
        console.log(`[${apiType}] Memanggil API: ${endpointURL}`);
        const response = await axios(options);

        // Jika respons sukses
        if (response.data) {
            console.log(`[${apiType}] Data berhasil diterima. Status: ${response.status}`);
            res.status(response.status).json(response.data);
        } else {
            console.warn(`[${apiType}] RESPON KOSONG/NULL. Status: ${response.status}`);
            res.status(response.status).json({ message: "Panggilan sukses, tetapi data yang dikembalikan kosong.", response_data_raw: response.data });
        }
    } catch (error) {
        if (error.response) {
            // Penanganan error dari API (4xx atau 5xx)
            const errMsg = error.response.data.response_message || error.response.statusText || 'Kesalahan dari API';
            console.error(`[${apiType}] GAGAL DENGAN STATUS ${error.response.status}. Pesan API: ${errMsg}`);

            return res.status(error.response.status).json({
                message: `Gagal mendapatkan ${apiType}.`,
                details: error.response.data,
                signature_failed_debug: {
                    endpoint_path: endpointPath,
                    method: method,
                    timestamp_header: timestampHeader,
                    timestamp_sig: timestampSig,
                    signature_payload_used: signaturePayload,
                }
            });
        }
        // ✅ PERBAIKAN: Penanganan error internal atau jaringan
        console.error(`[${apiType}] Kesalahan server internal atau jaringan:`, error.message);
        res.status(500).json({
            message: 'Kesalahan server internal atau jaringan.',
            details: error.message // Pastikan error.message digunakan
        });
    }
}

// ----------------------------------------------------------------------------------------
// --- ENDPOINT DEFINITIONS ---
// ----------------------------------------------------------------------------------------

// 1. ENDPOINT: Mendapatkan Access Token (Debugging - GET)
app.get('/api/get-access-token', async (req, res) => {
    console.log("--- Memulai Proses Get Access Token ---");
    try {
        const accessToken = await getAccessToken();
        res.status(200).json({ access_token: accessToken });
    } catch (error) {
        console.error("Error di /api/get-access-token:", error.message);
        res.status(500).json({ message: error.message });
    }
});

// 2. 💰 ENDPOINT: Client Balance (GET)
app.get('/api/client-balance', async (req, res) => {
    const apiType = 'CLIENT_BALANCE';
    const endpointPath = '/v1/open-api/balance';
    const endpointURL = BALANCE_ENDPOINT;

    const requestBody = {};

    console.log(`--- Memulai Proses Get ${apiType} ---`);
    callSignedApi(apiType, endpointURL, endpointPath, METHOD_GET, requestBody, res);
});


// 3. ENDPOINT: Mendapatkan Detail Atraksi (POST)
app.post('/api/get-attraction-detail', async (req, res) => {
    const apiType = 'ATRAKSI';
    const endpointPath = '/v1/open-api/attractions/detail';
    const endpointURL = ATTRACTIONS_DETAIL_ENDPOINT;
    const requestBody = { product_code: PRODUCT_CODE_ATTRACTION };

    console.log(`--- Memulai Proses Get Product ${apiType} ---`);
    callSignedApi(apiType, endpointURL, endpointPath, METHOD_POST, requestBody, res);
});

// 4. 🚉 ENDPOINT: Boarding Location (POST)
app.post('/api/transports/boarding-location', async (req, res) => {
    const apiType = 'BOARDING_LOCATION';
    const endpointPath = '/v1/open-api/transports/sources';
    const endpointURL = BOARDING_LOCATION_ENDPOINT;

    const { product_code, keyword } = req.body;
    if (!product_code) return res.status(400).json({ message: "**product_code** wajib diisi." });

    // ✅ Penting: Pastikan urutan kunci adalah product_code lalu keyword saat objek dibuat
    let requestBody = { product_code: product_code.toUpperCase() };
    if (keyword) {
        requestBody.keyword = keyword;
    }

    console.log(`--- Memulai Proses Get Transport Location (${apiType}) ---`);
    callSignedApi(apiType, endpointURL, endpointPath, METHOD_POST, requestBody, res);
});

// 5. 📍 ENDPOINT: Destination Location (POST)
app.post('/api/transports/destination-location', async (req, res) => {
    const apiType = 'DESTINATION_LOCATION';
    const endpointPath = '/v1/open-api/transports/destinations';
    const endpointURL = DESTINATION_LOCATION_ENDPOINT;

    const { product_code, keyword } = req.body;
    if (!product_code) return res.status(400).json({ message: "**product_code** wajib diisi." });

    // ✅ Penting: Pastikan urutan kunci adalah product_code lalu keyword saat objek dibuat
    let requestBody = { product_code: product_code.toUpperCase() };
    if (keyword) {
        requestBody.keyword = keyword;
    }

    console.log(`--- Memulai Proses Get Transport Location (${apiType}) ---`);
    callSignedApi(apiType, endpointURL, endpointPath, METHOD_POST, requestBody, res);
});

// --- SERVER LISTENER ---
app.listen(PORT, () => {
    console.log(`\n======================================================`);
    console.log(`🚀 Server Klikoo B2B berjalan di http://localhost:${PORT}`);
    console.log(`======================================================`);
    console.log(`\n📌 Endpoint Tersedia:`);
    console.log(`- SALDO (GET): http://localhost:${PORT}/api/client-balance`);
    console.log(`- Boarding (POST): http://localhost:${PORT}/api/transports/boarding-location`);
    console.log(`- Destination (POST): http://localhost:${PORT}/api/transports/destination-location`);
    console.log(`\n✅ LANGKAH BERIKUTNYA: Jalankan CURL berikut:`);
    console.log(`curl -X POST 'http://localhost:${PORT}/api/transports/destination-location' -H 'Content-Type: application/json' -d '{"product_code": "BUS", "keyword": "bandung"}'`);
});