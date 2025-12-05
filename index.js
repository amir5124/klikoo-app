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
const mysql = require('mysql2/promise');
const bodyParser = require('body-parser');
app.use(cors());
app.use(bodyParser.json());


app.use(express.json());

// --- KONSTANTA UTAMA KLIKOO API ---
// Hanya domain tanpa prefix tambahan
const BASE_URL = 'pvpapi.klikoo.id';

// Helper untuk membangun endpoint otomatis
const API = (path) => `https://${BASE_URL}/klikoo-b2b${path}`;

// ==========================
// ENDPOINT KONSTANTA
// ==========================
const AUTH_SIGNATURE_ENDPOINT = API('/v1/open-api/auth-signature');
const ACCESS_TOKEN_ENDPOINT = API('/v1/open-api/access-token');
const BALANCE_ENDPOINT = API('/v1/open-api/balance');
const ATTRACTIONS_DETAIL_ENDPOINT = API('/v1/open-api/attractions/detail');
const BOARDING_LOCATION_ENDPOINT = API('/v1/open-api/transports/sources');
const DESTINATION_LOCATION_ENDPOINT = API('/v1/open-api/transports/destinations');
const TRIPS_ENDPOINT = API('/v1/open-api/transports/trips');
const TRIP_DETAIL_ENDPOINT = API('/v1/open-api/transports/trips-detail');
const BLOCK_SEAT_ENDPOINT = API('/v1/open-api/transports/block-seat');
const BOOK_TICKET_ENDPOINT = API('/v1/open-api/transports/book');


// Kredensial Anda
const CLIENT_ID = 'f090bd38-6e1f-4675-b4e9-a37e5965f527';
const CLIENT_SECRET = 't0oeiqex8qh7z1urbyvyjng7mri5t1bw';
const PRIVATE_KEY_FILE = 'privatekey.pem';

const PRODUCT_CODE_ATTRACTION = "ATRAKSI-DANCER";
const METHOD_POST = 'POST';
const METHOD_GET = 'GET';

const DB_CONFIG = {
    host: '103.55.39.44',
    user: 'linkucoi_klikoo', // Contoh: root
    password: 'E+,,zAIh6VNI', // Contoh: password123
    database: 'linkucoi_klikoo',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

let pool;
try {
    pool = mysql.createPool(DB_CONFIG);
    console.log("MySQL connection pool initialized successfully.");
} catch (error) {
    console.error("Failed to initialize MySQL pool:", error);
    process.exit(1); // Stop the application if DB connection fails
}
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
        // Gunakan JSON.stringify() untuk menghasilkan string JSON dari payload
        // Kunci di payload HARUS diurutkan secara leksikografis, tapi Klikoo sepertinya TIDAK mewajibkan di JS.
        // Cukup gunakan payload yang sama dengan yang dikirim ke API.
        stringToHash = JSON.stringify(payload);
        console.log(`[SIG-DEBUG] JSON.stringify Payload (Digunakan untuk Hashing): ${stringToHash}`);
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
async function callSignedApi(apiType, endpointURL, endpointPath, method, requestBody, callback) {
    let accessToken;
    try {
        accessToken = await getAccessToken();
    } catch (error) {
        return callback({
            response_code: "500",
            response_message: `Gagal mendapatkan ${apiType} karena masalah Access Token.`,
            data: null,
            error
        });
    }

    const token = accessToken;

    const timestampHeader = moment().format('YYYY-MM-DDTHH:mm:ss.000+07:00');
    const timestampSig = timestampHeader;

    const signaturePayload = (method === METHOD_GET) ? {} : requestBody;

    let digitalSignature;
    try {
        digitalSignature = generateDigitalSignature(method, endpointPath, token, signaturePayload, timestampSig);
    } catch (error) {
        console.error(`Kesalahan menghitung Digital Signature untuk ${apiType}:`, error.message);
        return callback({
            response_code: "500",
            response_message: "Gagal menghitung Digital Signature.",
            data: null,
            error
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
    console.log(`[${apiType}] Request Body Sent: ${JSON.stringify(requestBody)}`);
    console.log(`[${apiType}] Memanggil API: ${endpointURL}`);

    try {
        const response = await axios(options);

        console.log(`[${apiType}] Data berhasil diterima. Status: ${response.status}`);

        return callback(response.data);

    } catch (error) {

        if (error.response) {
            console.error(`[${apiType}] ERROR ${error.response.status}:`, error.response.data);
            return callback(error.response.data);
        }

        console.error(`[${apiType}] ERROR INTERNAL:`, error.message);
        return callback({
            response_code: "500",
            response_message: "Kesalahan server internal atau jaringan",
            data: null,
            error: error.message
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

    if (!product_code) {
        return res.status(400).json({
            response_code: "40000001",
            response_message: "product_code wajib diisi.",
            data: null
        });
    }

    // LOG Request
    console.log(`\n========== REQUEST ${apiType} ==========`);
    console.log("Endpoint:", endpointURL + endpointPath);
    console.log("Body:", { product_code, keyword });
    console.log("========================================\n");

    callSignedApi(
        apiType,
        endpointURL,
        endpointPath,
        METHOD_POST,
        { product_code: product_code.toUpperCase(), keyword },
        (apiResponse) => {

            // LOG Response
            console.log(`\n********** RESPONSE ${apiType} **********`);
            console.log("Raw Response:");
            console.log(JSON.stringify(apiResponse, null, 2));
            console.log("****************************************\n");

            // Send formatted response
            return res.status(200).json({
                response_code: apiResponse?.response_code || "200",
                response_message: apiResponse?.response_message || "Success",
                data: apiResponse?.data || null
            });
        }
    );
});


// 5. 📍 ENDPOINT: Destination Location (POST)
app.post('/api/transports/destination-location', async (req, res) => {
    const apiType = 'DESTINATION_LOCATION';
    const endpointPath = '/v1/open-api/transports/destinations';
    const endpointURL = DESTINATION_LOCATION_ENDPOINT;

    const { product_code, keyword } = req.body;

    if (!product_code) {
        return res.status(400).json({
            response_code: "40000001",
            response_message: "product_code wajib diisi.",
            data: null
        });
    }

    // buat request body dengan urutan yang benar
    const requestBody = {
        product_code: product_code.toUpperCase(),
        keyword: keyword || ""   // aman walaupun kosong
    };

    // LOG Request
    console.log(`\n========== REQUEST ${apiType} ==========`);
    console.log("Endpoint:", endpointURL + endpointPath);
    console.log("Request Body:", JSON.stringify(requestBody, null, 2));
    console.log("========================================\n");

    callSignedApi(
        apiType,
        endpointURL,
        endpointPath,
        METHOD_POST,
        requestBody,
        (apiResponse) => {

            // LOG Response
            console.log(`\n********** RESPONSE ${apiType} **********`);
            console.log("Raw Response:");
            console.log(JSON.stringify(apiResponse, null, 2));
            console.log("****************************************\n");

            return res.status(200).json({
                response_code: apiResponse?.response_code || "200",
                response_message: apiResponse?.response_message || "Success",
                data: apiResponse?.data || null
            });
        }
    );
});


// 6. 🚌 ENDPOINT: Transport Trips / Search Schedule (POST)
app.post('/api/transports/trips', async (req, res) => {
    const apiType = 'TRANSPORT_TRIPS';
    const endpointPath = '/v1/open-api/transports/trips';
    const endpointURL = TRIPS_ENDPOINT;

    // Data wajib dari frontend
    const { product_code, source_id, destination_id, travel_date } = req.body;

    if (!product_code || !source_id || !destination_id || !travel_date) {
        return res.status(400).json({
            message: "product_code, source_id, destination_id, dan travel_date wajib diisi untuk mencari trips."
        });
    }

    // Payload final untuk API Klikoo
    const requestBody = {
        product_code: product_code.toUpperCase(),
        source_id: source_id,
        source_type: "CITY",
        destination_id: destination_id,
        destination_type: "CITY",
        total_seat: 1,
        date: travel_date,
        pagination: {
            limit: 100,
            page: 1,
            sort: {
                field: "boarding_time",
                value: "asc"
            },
            search: []
        }
    };

    // ==== LOG REQUEST ====
    console.log(`\n========== REQUEST ${apiType} ==========`);
    console.log("Endpoint:", endpointURL + endpointPath);
    console.log("Request Body:");
    console.log(JSON.stringify(requestBody, null, 2));
    console.log("========================================\n");

    callSignedApi(
        apiType,
        endpointURL,
        endpointPath,
        METHOD_POST,
        requestBody,
        (apiResponse) => {

            // ==== LOG RESPONSE ====
            console.log(`\n********** RESPONSE ${apiType} **********`);
            console.log("Raw Response:");
            console.log(JSON.stringify(apiResponse, null, 2));
            console.log("****************************************\n");

            return res.status(200).json({
                response_code: apiResponse?.response_code || "200",
                response_message: apiResponse?.response_message || "Success",
                data: apiResponse?.data || null
            });
        }
    );
});

// ----------------------------------------------------------------------------------------
// ✅ 7. 🚌 ENDPOINT BARU: Trip Detail (POST)
// ----------------------------------------------------------------------------------------
app.post('/api/transports/trips-detail', async (req, res) => {
    const apiType = 'TRIP_DETAIL';
    const endpointPath = '/v1/open-api/transports/trips-detail';
    const endpointURL = TRIP_DETAIL_ENDPOINT;

    const { product_code, trip_id } = req.body;

    if (!product_code || !trip_id) {
        return res.status(400).json({
            response_code: "40000001",
            response_message: "product_code dan trip_id wajib diisi.",
            data: null
        });
    }

    const requestBody = {
        product_code: product_code.toUpperCase(),
        trip_id
    };

    // ==== LOG Request ====
    console.log(`\n========== REQUEST ${apiType} ==========`);
    console.log("Endpoint:", endpointURL + endpointPath);
    console.log("Body:", requestBody);
    console.log("========================================\n");

    callSignedApi(
        apiType,
        endpointURL,
        endpointPath,
        METHOD_POST,
        requestBody,
        (apiResponse) => {

            // ==== LOG Response ====
            console.log(`\n********** RESPONSE ${apiType} **********`);
            console.log("Raw Response:");
            console.log(JSON.stringify(apiResponse, null, 2));
            console.log("****************************************\n");

            return res.status(200).json({
                response_code: apiResponse?.response_code || "200",
                response_message: apiResponse?.response_message || "Success",
                data: apiResponse?.data || null
            });
        }
    );
});


// ----------------------------------------------------------------------------------------
// ✅ 8. 💺 ENDPOINT BARU: Block Seat (POST)
// ----------------------------------------------------------------------------------------
app.post('/api/transports/block-seat', async (req, res) => {
    const apiType = 'BLOCK_SEAT';
    const endpointPath = '/v1/open-api/transports/block-seat';
    const endpointURL = BLOCK_SEAT_ENDPOINT;

    const {
        product_code, selling_price, partner_reference_no,
        order_detail, departure, return: returnTrip
    } = req.body;

    // Validasi field wajib
    if (!product_code || !selling_price || !partner_reference_no || !order_detail || !departure) {
        return res.status(400).json({
            response_code: "40000001",
            response_message: "product_code, selling_price, partner_reference_no, order_detail, dan departure wajib diisi.",
            data: null
        });
    }

    // Payload request
    const requestBody = {
        product_code: product_code.toUpperCase(),
        selling_price,
        partner_reference_no,
        order_detail,
        departure,
        ...(returnTrip && { return: returnTrip })
    };

    // Logging REQUEST
    console.log(`\n========== REQUEST ${apiType} ==========`);
    console.log("Endpoint:", endpointURL + endpointPath);
    console.log("Body Sent:", JSON.stringify(requestBody, null, 2));
    console.log("========================================\n");

    callSignedApi(apiType, endpointURL, endpointPath, METHOD_POST, requestBody, (apiResponse) => {

        // Logging RESPONSE
        console.log(`\n********** RESPONSE ${apiType} **********`);
        console.log("Raw Response:");
        console.log(JSON.stringify(apiResponse, null, 2));
        console.log("****************************************\n");

        return res.status(200).json({
            response_code: apiResponse?.response_code || "200",
            response_message: apiResponse?.response_message || "Success",
            data: apiResponse?.data || null
        });
    });
});

// ----------------------------------------------------------------------------------------
// ✅ 9. 🎟️ ENDPOINT BARU: Book Ticket (POST)
app.post('/api/transports/book-ticket', async (req, res) => {
    const apiType = 'BOOK_TICKET';
    const endpointPath = '/v1/open-api/transports/book';
    const endpointURL = BOOK_TICKET_ENDPOINT;

    // Ambil User-Agent dari body request (dikirim dari frontend sebagai user identifier/username)
    const userAgent = req.body.useragen;
    console.log(`User Identifier (from body/useragen) received: ${userAgent}`);


    // Gunakan try-catch untuk menangani error database dan lainnya
    try {
        const { transaction_id } = req.body;

        // Validasi wajib
        if (!transaction_id) {
            return res.status(400).json({
                response_code: "40000001",
                response_message: "**transaction_id** wajib diisi.",
                data: null
            });
        }

        // Build request ke Klikoo
        const requestBody = {
            transaction_id: String(transaction_id)
        };

        // Logging REQUEST sebelum ke Klikoo
        console.log(`\n========== REQUEST ${apiType} ==========`);
        console.log("Endpoint:", endpointURL + endpointPath);
        console.log("Body Sent:", JSON.stringify(requestBody, null, 2));
        console.log("========================================\n");

        // Panggil Klikoo API
        callSignedApi(apiType, endpointURL, endpointPath, METHOD_POST, requestBody, async (apiResponse) => {

            // Logging RESPONSE dari Klikoo
            console.log(`\n********** RESPONSE ${apiType} **********`);
            console.log("Raw Response:");
            console.log(JSON.stringify(apiResponse, null, 2));
            console.log("****************************************\n");

            const { response_code, response_message, data } = apiResponse;

            // ==============================================================
            // LOGIKA PENYIMPANAN KE DATABASE (Jika API berhasil)
            // ==============================================================
            // Cek kondisi sukses dari API (kode 201052001 dan status SUCCESS)
            if (response_code === "201052001" && data?.status === "SUCCESS") {
                console.log("API Success. Preparing to save to DB...");

                const {
                    transaction_id: klikoo_transaction_id,
                    status,
                    booking_codes
                } = data;

                // Query SQL untuk menyimpan data booking, termasuk user_agent
                const sql = `
                    INSERT INTO ticket_bookings 
                    (transaction_id, api_response_code, api_response_message, status, departure_code, return_code, user_agent)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON DUPLICATE KEY UPDATE
                    api_response_code = VALUES(api_response_code),
                    api_response_message = VALUES(api_response_message),
                    status = VALUES(status),
                    departure_code = VALUES(departure_code),
                    return_code = VALUES(return_code),
                    user_agent = VALUES(user_agent); 
                `;

                // Array nilai yang akan di-bind ke query SQL
                const values = [
                    klikoo_transaction_id,
                    response_code,
                    response_message,
                    status,
                    booking_codes?.departure || null,
                    booking_codes?.return || null,
                    userAgent || null // Menggunakan userAgent dari req.body.useragen
                ];

                try {
                    // Eksekusi query INSERT/UPDATE
                    const [result] = await pool.execute(sql, values);
                    console.log(`[DB SUCCESS] Booking saved/updated. Insert ID: ${result.insertId || 'N/A'}, Affected Rows: ${result.affectedRows}`);
                } catch (dbError) {
                    console.error("[DB ERROR] Failed to save booking to database:", dbError.message);
                    // Lanjutkan untuk mengirim respons ke klien meskipun DB error
                }
            }
            // ==============================================================

            // Kirim respons akhir ke klien (dari API eksternal)
            return res.status(200).json({
                response_code: response_code || "200",
                response_message: response_message || "Success",
                data: data || null
            });
        });

    } catch (error) {
        // Menangani error tak terduga (misalnya JSON parsing error atau pool error)
        console.error("Internal Server Error in route:", error);
        return res.status(500).json({
            response_code: "50000000",
            response_message: "Internal Server Error",
            data: null
        });
    }
});


// ROUTE 4.2: GET HISTORY by User Agent (GET) - ROUTE BARU
app.get('/api/transports/history/:useragen', async (req, res) => {
    const userAgent = req.params.useragen;
    console.log(`\n========== REQUEST HISTORY by User Agent ==========`);
    console.log(`Fetching history for user: ${userAgent}`);

    if (!userAgent) {
        return res.status(400).json({
            response_code: "40000002",
            response_message: "**useragen** wajib diisi di path URL.",
            data: []
        });
    }

    // Query untuk mengambil semua kolom data booking berdasarkan user_agent
    const sql = `
        SELECT 
            id, 
            transaction_id, 
            api_response_code, 
            api_response_message, 
            status, 
            departure_code, 
            return_code, 
            user_agent, 
            created_at 
        FROM 
            ticket_bookings 
        WHERE 
            user_agent = ?
        ORDER BY 
            created_at DESC;
    `;

    try {
        const [rows] = await pool.execute(sql, [userAgent]);

        console.log(`[DB SUCCESS] Found ${rows.length} records for user ${userAgent}`);

        // Mengirim data riwayat dalam format JSON
        return res.status(200).json({
            response_code: "20000000",
            response_message: "History berhasil diambil.",
            data: rows // rows adalah array of objects dari hasil query
        });

    } catch (error) {
        console.error("Internal Server Error fetching history:", error);
        return res.status(500).json({
            response_code: "50000000",
            response_message: "Gagal mengambil data history dari database.",
            data: null
        });
    }
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
    console.log(`- JADWAL (POST): http://localhost:${PORT}/api/transports/trips`);
    // ✅ ENDPOINT BARU
    console.log(`- DETAIL TRIP (POST): http://localhost:${PORT}/api/transports/trips-detail`);
    console.log(`- BLOCK SEAT (POST): http://localhost:${PORT}/api/transports/block-seat`);
    console.log(`- BOOK TICKET (POST): http://localhost:${PORT}/api/transports/book-ticket`);
    console.log(`\n✅ LANGKAH BERIKUTNYA: Coba panggil salah satu endpoint baru:`);
    console.log(`curl -X POST 'http://localhost:${PORT}/api/transports/trips-detail' -H 'Content-Type: application/json' -d '{"product_code": "BUS", "trip_id": 188328}'`);
});