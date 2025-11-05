const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const serverless = require('serverless-http'); // Para Vercel/Netlify

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
// 
app.post('/api/webhook', (req, res) => {
    // Primero, validar la firma de seguridad
    if (!validateSignature(req)) {
        console.warn("Validación de firma fallida. Solicitud descartada.");
        return res.sendStatus(403); // Prohibido
    }

    const body = req.body;

    // Verificar que es un evento de WhatsApp
    if (body.object === 'whatsapp_business_account') {
        body.entry.forEach(entry => {
            const changes = entry.changes;
            if (changes && changes && changes.value && changes.value.messages) {
                const message = changes.value.messages;
                if (message.type === 'text') {
                    const from = message.from; // Número del usuario
                    const messageId = message.id; // ID del mensaje
                    const textBody = message.text.body; // Texto del mensaje

                    console.log(`Mensaje de ${from} (ID: ${messageId}): ${textBody}`);

                    // *** AQUÍ VA LA LÓGICA DE IA (Fase 6) ***
                    // Ejemplo:
                    // const aiResponse = await getAIResponse(textBody);
                    
                    // *** AQUÍ VA EL ENVÍO DE RESPUESTA (Fase 7) ***
                    // Ejemplo:
                    // await sendWhatsAppReply(from, aiResponse, messageId);
                }
            }
        });
        res.sendStatus(200); // Responder OK a Meta
    } else {
        res.sendStatus(404); // No encontrado
    }
});

// === 3. Función de Seguridad (Validación de Firma) ===
// 
function validateSignature(req) {
    const signature = req.headers['x-hub-signature-256'];

    // --- NUEVA LÍNEA DE DIAGNÓSTICO ---
    console.log("Validación de Firma - Cabecera 'x-hub-signature-256' RECIBIDA:", signature);
    // --- FIN DE LÍNEA DE DIAGNÓSTICO ---

    if (!signature) {
        console.warn("Validación de firma fallida: No se encontró la cabecera x-hub-signature-256.");
        return false;
    }

    const elements = signature.split('=');
    const signatureHash = elements[2]; // El hash 'sha256' de Meta

    if (!signatureHash) {
        console.warn("Validación de firma fallida: Formato de cabecera inesperado.");
        return false;
    }

    const expectedHash = crypto
     .createHmac('sha256', APP_SECRET)
     .update(req.rawBody) // ¡Usar el cuerpo crudo! 
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
