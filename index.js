const express = require('express');
const axios = require('axios');
const moment = require('moment');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const CryptoJS = require('crypto-js'); // Untuk SHA256
const stableStringify = require('json-stable-stringify'); // Untuk Minify JSON yang konsisten

const app = express();
const PORT = 3000;

// Middleware untuk memproses JSON request body
app.use(express.json());

// --- KONSTANTA UTAMA KLIKOO API ---
const BASE_URL = 'pvpapi.stage.pvg.im/klikoo-b2b';
const AUTH_SIGNATURE_ENDPOINT = `https://${BASE_URL}/v1/open-api/auth-signature`;
const ACCESS_TOKEN_ENDPOINT = `https://${BASE_URL}/v1/open-api/access-token`;
const ATTRACTIONS_DETAIL_ENDPOINT = `https://${BASE_URL}/v1/open-api/attractions/detail`;
const CLIENT_ID = '8670d916-9d10-45b9-a091-82b9dedd9b53';
const CLIENT_SECRET = 'vylmiqtm91jq74ct537pdw5vqq05retj'; // Client Secret
const PRIVATE_KEY_FILE = 'privatekey.pem'; // Nama file kunci Anda
const PRODUCT_CODE_ATTRACTION = "ATRAKSI-DANCER";
// ------------------------------------


// --- FUNGSI UTILITY: MENGHITUNG DIGITAL SIGNATURE (HMAC-SHA512) ---
/**
 * Menghitung Digital Signature sesuai dokumentasi.
 * string_to_sign = METHOD:PATH:TOKEN:HASHED_PAYLOAD:TIMESTAMP
 */
function generateDigitalSignature(method, path, token, payload, timestamp) {
    // 1. Minify JSON (dengan urutan kunci yang stabil)
    const minifiedPayload = stableStringify(payload);

    // 2. hashed_payload = hexEncode(sha256(minifyJSON(payload)))
    const hashedPayload = CryptoJS.SHA256(minifiedPayload).toString(CryptoJS.enc.Hex);

    // 3. Bentuk string_to_sign
    const stringToSign = `${method}:${path}:${token}:${hashedPayload}:${timestamp}`;

    console.log(`[SIG-DIGITAL] String To Sign: ${stringToSign}`);

    // 4. Hitung HMAC-SHA512 dari string_to_sign menggunakan CLIENT_SECRET, lalu Base64 encode
    const hmac = crypto.createHmac('sha512', CLIENT_SECRET);
    hmac.update(stringToSign);
    const signatureBase64 = hmac.digest('base64');

    return signatureBase64;
}
// ------------------------------------------------------------------


// --- FUNGSI UTILITY: MENDAPATKAN AUTH SIGNATURE (LANGKAH 1) ---
async function getAuthSignature() {
    let privateKeyBase64;
    try {
        const privateKeyContent = fs.readFileSync(path.join(__dirname, PRIVATE_KEY_FILE), 'utf-8');
        privateKeyBase64 = Buffer.from(privateKeyContent).toString('base64');
    } catch (err) {
        throw new Error(`Gagal membaca Private Key: ${err.message}. Pastikan file ${PRIVATE_KEY_FILE} ada.`);
    }

    // Timestamp harus cocok dengan Open-Api-Timestamp Header
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
// ----------------------------------------------------------------------------------------


// --- FUNGSI UTILITY: MENDAPATKAN ACCESS TOKEN (LANGKAH 2) ---
async function getAccessToken() {
    let authData;
    try {
        authData = await getAuthSignature();
    } catch (error) {
        throw new Error(`Kesalahan pra-autentikasi (Auth Signature): ${error.message}`);
    }

    const requestBody = {
        grant_type: "client_credentials",
        additional_info: { client_id: CLIENT_ID, client_secret: CLIENT_SECRET }
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

        // ✅ Penanganan yang lebih robust untuk 'access_token'
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
            console.error("[TOKEN] Error Response Penuh:", error.response.data);
            throw new Error(`Error saat memanggil API Access Token (${error.response.status}): ${errMsg}`);
        }
        throw new Error(`Gagal API Access Token: ${error.message}`);
    }
}
// ----------------------------------------------------------------------------------------


// --- 1. ENDPOINT: Debug/Verifikasi Auth Signature ---
app.get('/api/get-auth-signature', async (req, res) => {
    try {
        const result = await getAuthSignature();
        res.status(200).json(result);
    } catch (error) {
        console.error("Error di /api/get-auth-signature:", error.message);
        res.status(500).json({ message: error.message });
    }
});


// --- 2. ENDPOINT: Mendapatkan Access Token ---
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


// --- 3. ENDPOINT: Mendapatkan Detail Atraksi (Menggunakan Digital Signature) ---
app.get('/api/get-attraction-detail', async (req, res) => {
    console.log("--- Memulai Proses Get Product Attraction ---");

    let accessToken;
    try {
        // Langkah 1 & 2: Dapatkan Access Token terlebih dahulu
        accessToken = await getAccessToken();
    } catch (error) {
        console.error("Kesalahan Access Token:", error.message);
        return res.status(500).json({
            message: 'Gagal mendapatkan Detail Atraksi karena masalah Access Token.',
            details: error.message
        });
    }

    // Langkah 3: Hitung Digital Signature

    // Nilai untuk perhitungan Signature dan Request Body
    const method = 'POST';
    const path = '/v1/open-api/attractions/detail';
    const token = accessToken;
    const requestBody = { product_code: PRODUCT_CODE_ATTRACTION };
    // Timestamp harus sama di Header dan String to Sign. Format: yyyy-MM-dd'T'HH:mm:ss+Z
    const timestamp = moment().format('YYYY-MM-DDTHH:mm:ss+07:00');

    let digitalSignature;
    try {
        digitalSignature = generateDigitalSignature(method, path, token, requestBody, timestamp);
        console.log(`[DETAIL] Digital Signature Final: ${digitalSignature}`);
    } catch (error) {
        console.error("Kesalahan menghitung Digital Signature:", error.message);
        return res.status(500).json({
            message: 'Gagal menghitung Digital Signature.',
            details: error.message
        });
    }

    // Buat Header Request
    const headers = {
        'Content-Type': 'application/json',
        'Open-Api-Timestamp': timestamp,
        'Open-Api-Signature': digitalSignature,
        'Authorization': `Bearer ${accessToken}`
    };

    const options = {
        method: method,
        url: ATTRACTIONS_DETAIL_ENDPOINT,
        headers: headers,
        data: requestBody
    };

    console.log("[DETAIL] Request Headers:", headers);
    console.log("[DETAIL] Request Body:", requestBody);

    try {
        console.log(`[DETAIL] Memanggil API: ${ATTRACTIONS_DETAIL_ENDPOINT}`);

        const response = await axios(options);

        // 💡 PENAMBAHAN DEBUGGING BARU 💡
        console.log(`[DETAIL] Response Status: ${response.status}`);
        console.log(`[DETAIL] Response Headers:`, response.headers);
        console.log(`[DETAIL] Response Data (Raw):`, response.data);
        console.log(`[DETAIL] Type of Response Data: ${typeof response.data}`);
        // 💡 END DEBUGGING BARU 💡

        if (response.data && (typeof response.data === 'object' || response.data.length > 0)) {
            console.log("[DETAIL] Detail Atraksi berhasil diterima.");
            // Kirim response data yang sudah di-parse
            res.status(response.status).json(response.data);
        } else {
            // Jika status 2xx tapi body kosong
            console.warn("[DETAIL] RESPON KOSONG/NULL: Status sukses, tetapi body kosong.");
            res.status(response.status).json({
                message: "Panggilan sukses, tetapi data yang dikembalikan kosong. Mungkin 'product_code' tidak ditemukan atau data produknya kosong.",
                response_data_raw: response.data
            });
        }


    } catch (error) {
        if (error.response) {
            const errMsg = error.response.data.response_message || error.response.statusText || 'Kesalahan dari API Detail Atraksi';
            console.error(`[DETAIL] GAGAL DENGAN STATUS ${error.response.status}. Pesan API: ${errMsg}`);
            console.error("[DETAIL] Error Response Penuh:", error.response.data);

            return res.status(error.response.status).json({
                message: 'Gagal mendapatkan Detail Atraksi.',
                details: error.response.data
            });
        }
        console.error("[DETAIL] Kesalahan server internal atau jaringan:", error.message);
        res.status(500).json({
            message: 'Kesalahan server internal atau jaringan.',
            details: error.message
        });
    }
});

// --- SERVER LISTENER ---
app.listen(PORT, () => {
    console.log(`🚀 Server berjalan di http://localhost:${PORT}`);
    console.log(`Akses API:`);
    console.log(`- Token: http://localhost:${PORT}/api/get-access-token`);
    console.log(`- Atraksi: http://localhost:${PORT}/api/get-attraction-detail`);
});