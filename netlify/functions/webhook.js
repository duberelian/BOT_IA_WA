const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const serverless = require('serverless-http'); // Para Vercel/Netlify
// Añadir en la parte superior del archivo
const { GoogleGenerativeAI } = require('@google/generative-ai');
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });
// Añadir en la parte superior del archivo
const axios = require('axios');
const PHONE_NUMBER_ID = process.env.PHONE_NUMBER_ID;

const app = express();

// === CONSTANTES (Leer desde Variables de Entorno) ===
const VERIFY_TOKEN = process.env.VERIFY_TOKEN;
const WHATSAPP_TOKEN = process.env.WHATSAPP_TOKEN;
const APP_SECRET = process.env.APP_SECRET;

// --- Requisito Crítico: Cuerpo Crudo (Raw Body) ---
// Para validar la firma de seguridad de Meta, necesitamos el "cuerpo crudo" (raw body)
// de la solicitud POST, no el JSON ya analizado (parseado).
// Usamos bodyParser.json con una función 'verify' para capturar el búfer
// crudo y almacenarlo en 'req.rawBody' antes de que se analice.
app.use(bodyParser.json({
    verify: (req, res, buf) => {
        req.rawBody = buf;
    }
}));

// === 1. Endpoint GET /webhook (Verificación de Meta) ===
// 
app.get('/api/webhook', (req, res) => {
    const mode = req.query['hub.mode'];
    const token = req.query['hub.verify_token'];
    const challenge = req.query['hub.challenge'];

    if (mode === 'subscribe' && token === VERIFY_TOKEN) {
        console.log("Webhook verificado exitosamente!");
        res.status(200).send(challenge);
    } else {
        console.error("Fallo la verificación del webhook.");
        res.sendStatus(403);
    }
});

// === 2. Endpoint POST /webhook (Recepción de Mensajes) ===
// [2]
// REEMPLAZO COMPLETO: Lógica de iteración robusta con for...of
app.post('/api/webhook', async (req, res) => {
    
    // 1. Validar la firma (esto ya funciona)
    if (!validateSignature(req)) {
        console.warn("Validación de firma fallida. Solicitud descartada.");
        return res.sendStatus(403);
    }

    const body = req.body;

    // 2. Verificar que es un evento de WhatsApp
    if (body.object === 'whatsapp_business_account') {
        try {
            // 3. Iterar sobre las entradas (entries)
            if (body.entry) {
                for (const entry of body.entry) {
                    // 4. Iterar sobre los cambios (changes)
                    if (entry.changes) {
                        for (const change of entry.changes) {
                            // 5. Verificar que el cambio tiene mensajes
                            if (change.value && change.value.messages) {
                                // 6. Iterar sobre los mensajes (puede haber varios)
                                for (const message of change.value.messages) {
                                    
                                    if (message.type === 'text') {
                                        const from = message.from;
                                        const messageId = message.id;
                                        const textBody = message.text.body;

                                        // --- ¡AQUÍ ESTÁ EL LOG! ---
                                        console.log(`Mensaje de ${from} (ID: ${messageId}): ${textBody}`);

                                        // 7. Llamar a la IA (Fase 6)
                                        const aiResponse = await getAIResponse(textBody);
                                        
                                        // 8. Enviar respuesta (Fase 7)
                                        await sendWhatsAppReply(from, aiResponse, messageId);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // 9. Responder 200 OK a Meta
            res.sendStatus(200);
        } catch (error) {
            console.error("Error procesando el webhook:", error);
            res.sendStatus(500); // Informar de un error si algo falla
        }
    } else {
        // No es un evento de WhatsApp
        res.sendStatus(404);
    }
});

// === 3. Función de Seguridad (Validación de Firma) ===
// [2]
function validateSignature(req) {
    const signature = req.headers['x-hub-signature-256'];

    if (!signature) {
        console.warn("Validación de firma fallida: No se encontró la cabecera x-hub-signature-256.");
        return false;
    }

    // --- NUEVA LÓGICA (MÁS ROBUSTA) ---
    // En lugar de split('='), extraemos todo después de 'sha256='
    // El hash comienza en el 7mo caracter (índice 7)
    if (signature.length < 8 ||!signature.startsWith('sha256=')) {
        console.warn("Validación de firma fallida: Formato de cabecera inesperado (no 'sha256=').");
        return false;
    }

    // Extrae el "HASH"
    const signatureHash = signature.substring(7); 

    if (!signatureHash) {
        console.warn("Validación de firma fallida: Hash vacío.");
        return false;
    }
    // --- FIN DE NUEVA LÓGICA ---

    const expectedHash = crypto
     .createHmac('sha256', APP_SECRET)
     .update(req.rawBody) // ¡Usar el cuerpo crudo! [2]
     .digest('hex');

    const expectedHashBuffer = Buffer.from(expectedHash, 'hex');
    const signatureHashBuffer = Buffer.from(signatureHash, 'hex');

    if (signatureHashBuffer.length!== expectedHashBuffer.length) {
         console.warn("Validación de firma fallida: Longitudes de hash no coinciden.");
        return false;
    }

    return crypto.timingSafeEqual(signatureHashBuffer, expectedHashBuffer);
}
// Exportar para Serverless
module.exports.handler = serverless(app);

async function getAIResponse(userText) {
    try {
        // [29, 30]
        const chat = model.startChat({
            history: [
                // Opcional: Añadir un "system prompt"
                { role: "user", parts: [{ text: "Eres un asistente de IA amable y servicial." }] },
                { role: "model", parts: [{ text: "¡Entendido! Estoy listo para ayudar." }] }
            ],
        });
        const result = await chat.sendMessage(userText);
        const response = result.response;
        return response.text();
    } catch (error) {
        console.error("Error al llamar a la API de Gemini:", error);
        return "Lo siento, estoy teniendo problemas para conectar con mi cerebro de IA en este momento.";
    }
}



async function sendWhatsAppReply(to, text, messageId) {
    const url = `https://graph.facebook.com/v20.0/${PHONE_NUMBER_ID}/messages`;
    const headers = {
        'Authorization': `Bearer ${WHATSAPP_TOKEN}`,
        'Content-Type': 'application/json'
    };
    // [32, 34, 35]
    const body = {
        "messaging_product": "whatsapp",
        "recipient_type": "individual",
        "to": to,
        "type": "text",
        "text": {
            "preview_url": false,
            "body": text
        },
        // --- Respuesta Contextual  ---
        // Esto hace que el bot "cite" el mensaje original.
        "context": {
            "message_id": messageId 
        }
    };

    try {
        await axios.post(url, body, { headers: headers });
        console.log(`Respuesta enviada a ${to}`);
    } catch (error) {
        console.error("Error al enviar la respuesta de WhatsApp:", error.response? error.response.data : error.message);
    }
}


