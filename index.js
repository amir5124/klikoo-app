const express = require('express');
const axios = require('axios');
const moment = require('moment');
const fs = require('fs');
const path = require('path');
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
const PRODUCT_CODE_ATTRACTION = "ATRAKSI-DANCER"; // Product code untuk Detail Atraksi
// ------------------------------------


// --- FUNGSI HELPER: MENDAPATKAN AUTH SIGNATURE SECARA INTERNAL ---
/**
 * Fungsi Helper untuk mendapatkan Auth Signature dari API Klikoo.
 * Digunakan sebagai langkah otorisasi pra-panggilan untuk API lain.
 * @returns {Promise<{signature: string, timestamp: string}>}
 */
async function getAuthSignature() {
    let privateKeyBase64;

    // 1. Baca dan Encode Private Key
    try {
        const privateKeyContent = fs.readFileSync(path.join(__dirname, PRIVATE_KEY_FILE), 'utf-8');
        // Encoding Base64 (sesuai yang berhasil Anda uji)
        privateKeyBase64 = Buffer.from(privateKeyContent).toString('base64');
    } catch (err) {
        throw new Error(`Gagal membaca Private Key: ${err.message}. Pastikan file ${PRIVATE_KEY_FILE} ada.`);
    }

    // 2. Generate Timestamp
    const timestamp = moment().format('YYYY-MM-DDTHH:mm:ss.000+07:00');

    // 3. Panggil API Signature
    const requestBody = {
        client_id: CLIENT_ID,
        timestamp: timestamp,
        private_key: privateKeyBase64
    };

    const headers = {
        'Content-Type': 'application/json',
        'Open-Api-Timestamp': timestamp
    };

    const options = {
        method: 'POST',
        url: AUTH_SIGNATURE_ENDPOINT,
        headers: headers,
        data: requestBody
    };

    try {
        const response = await axios(options);
        const signature = response.data.signature || response.data.auth_signature || response.data.data?.signature;

        if (!signature) {
            console.error("[SIGNATURE] Respon berhasil, tapi properti 'signature' tidak ditemukan:", response.data);
            throw new Error("Properti 'signature' tidak ditemukan di response API Auth Signature.");
        }

        console.log(`[SIGNATURE] Auth Signature berhasil didapat.`);
        return { signature: signature, timestamp: timestamp };

    } catch (error) {
        if (error.response) {
            console.error(`[SIGNATURE] GAGAL DENGAN STATUS ${error.response.status}:`, error.response.data);
            const errMsg = error.response.data.response_message || error.response.statusText;
            throw new Error(`Auth Signature Gagal (${error.response.status}): ${errMsg}`);
        }
        throw new Error(`Gagal API Auth Signature: ${error.message}`);
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

    let authData;
    try {
        authData = await getAuthSignature();
    } catch (error) {
        console.error("Kesalahan pra-autentikasi (Auth Signature):", error.message);
        return res.status(500).json({
            message: 'Gagal mendapatkan Access Token karena masalah Auth Signature.',
            details: error.message
        });
    }

    const requestBody = {
        grant_type: "client_credentials",
        additional_info: {
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET
        }
    };

    const headers = {
        'Content-Type': 'application/json',
        'Open-Api-Timestamp': authData.timestamp,
        'Open-Api-Signature': authData.signature
    };

    const options = {
        method: 'POST',
        url: ACCESS_TOKEN_ENDPOINT,
        headers: headers,
        data: requestBody
    };

    try {
        console.log("[TOKEN] Memanggil API Access Token...");
        const response = await axios(options);

        console.log("[TOKEN] Access Token berhasil diterima.");
        res.status(response.status).json(response.data);

    } catch (error) {
        const errMsg = error.response?.data?.responseMessage || error.message;
        console.error("[TOKEN] Error saat memanggil API Access Token:", errMsg);

        if (error.response) {
            return res.status(error.response.status).json({
                message: 'Gagal mendapatkan Access Token.',
                details: error.response.data
            });
        }

        res.status(500).json({
            message: 'Kesalahan server internal atau jaringan.'
        });
    }
});


// --- 3. ENDPOINT: Mendapatkan Detail Atraksi ---
app.get('/api/get-attraction-detail', async (req, res) => {
    console.log("--- Memulai Proses Get Product Attraction ---");

    let authData;
    try {
        authData = await getAuthSignature();
        console.log("[DETAIL] Auth Signature berhasil didapat.");
    } catch (error) {
        console.error("Kesalahan pra-autentikasi (Auth Signature):", error.message);
        return res.status(500).json({
            message: 'Gagal mendapatkan Detail Atraksi karena masalah Auth Signature.',
            details: error.message
        });
    }

    const requestBody = {
        product_code: PRODUCT_CODE_ATTRACTION
    };

    const headers = {
        'Content-Type': 'application/json',
        'Open-Api-Timestamp': authData.timestamp,
        'Open-Api-Signature': authData.signature
    };

    const options = {
        method: 'POST', // Metode GET
        url: ATTRACTIONS_DETAIL_ENDPOINT,
        headers: headers,
        data: requestBody // GET dengan Body
    };

    // --- Penambahan Logging Request ---
    console.log("[DETAIL] Request Headers:", headers);
    console.log("[DETAIL] Request Body:", requestBody);
    // --- Akhir Penambahan Logging Request ---

    try {
        console.log(`[DETAIL] Memanggil API: ${ATTRACTIONS_DETAIL_ENDPOINT} dengan kode: ${PRODUCT_CODE_ATTRACTION}`);

        const response = await axios(options);

        console.log("[DETAIL] Detail Atraksi berhasil diterima.");

        // --- Penambahan Logging Response Body ---
        console.log("[DETAIL] Response Status:", response.status);
        console.log("[DETAIL] Response Body:", response.data);
        // --- Akhir Penambahan Logging Response Body ---

        res.status(response.status).json(response.data);

    } catch (error) {
        const errMsg = error.response?.data?.responseMessage || error.message;
        console.error("[DETAIL] Error saat memanggil API Attractions Detail:", errMsg);

        if (error.response) {
            // --- Penambahan Logging Error Response Body ---
            console.error("[DETAIL] Error Response Status:", error.response.status);
            console.error("[DETAIL] Error Response Body:", error.response.data);
            // --- Akhir Penambahan Logging Error Response Body ---

            return res.status(error.response.status).json({
                message: 'Gagal mendapatkan Detail Atraksi.',
                details: error.response.data
            });
        }

        res.status(500).json({
            message: 'Kesalahan server internal atau jaringan.'
        });
    }
});

// --- SERVER LISTENER ---
app.listen(PORT, () => {
    console.log(`🚀 Server berjalan di http://localhost:${PORT}`);
    console.log(`Akses API:`);
    console.log(`- Signature (Debug): http://localhost:${PORT}/api/get-auth-signature`);
    console.log(`- Token: http://localhost:${PORT}/api/get-access-token`);
    console.log(`- Atraksi: http://localhost:${PORT}/api/get-attraction-detail`);
});