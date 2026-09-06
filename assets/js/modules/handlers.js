import * as state from './state.js';
import * as ui from './ui.js';
import * as crypto from './crypto.js';
import { elements } from './dom.js';
import { HEADER_MARKER, SEPARATOR } from './config.js';

export async function handleEncodeText() {
    const text = elements.inputText.value.trim();
    if (!text) return ui.showToast('يرجى إدخال نص للتشفير', 'error');

    try {
        ui.showToast('جاري التشفير...', 'info', 1000);
        const useCompression = elements.useCompression.checked;
        const useEncryption = elements.useEncrypt.checked;
        const password = elements.password.value;

        const origSizeBytes = crypto.getEncoder().encode(text).length;

        let payloadBytes = useCompression
            ? crypto.AdvancedCompression.compress(text)
            : crypto.getEncoder().encode(text);

        const isActuallyCompressed = useCompression && payloadBytes.length < origSizeBytes;
        if (useCompression && !isActuallyCompressed) {
            payloadBytes = crypto.getEncoder().encode(text);
        }

        let encResult = null;
        if (useEncryption && password) {
            const iterations = getEncryptionIterations();
            encResult = await crypto.AdvancedEncryption.encrypt(payloadBytes, password, iterations);
            payloadBytes = encResult.encrypted;
        }

        // Use v3 compact binary payload format
        const combinedData = packPayloadV3(
            payloadBytes,
            origSizeBytes,
            isActuallyCompressed,
            Boolean(useEncryption && password),
            encResult
        );

        const result = crypto.encodeBytesToEmoji(state.currentActiveEmoji, combinedData);
        elements.output.value = result;
        ui.updateStats(origSizeBytes, payloadBytes.length);
        ui.showResultsSection();

        if (state.appSettings.autoCopyEncodedEmoji) {
            await ui.copyToClipboard(result, elements.copyBtn);
        }
        ui.showToast('تم تشفير النص بنجاح', 'success');
        addHistoryEntry(text, result);
    } catch (err) {
        console.error('Encoding error:', err);
        ui.showToast(`خطأ في التشفير: ${err.message}`, 'error');
    }
}

export async function handleDecodeText() {
    const src = elements.inputText.value.trim();
    if (!src) return ui.showToast('يرجى إدخال نص مشفر', 'error');

    ui.showToast('جاري فك التشفير...', 'info');
    try {        const result = await decodeMessage(src);
        if (result && result.text !== null) {
            elements.output.value = result.text;
            ui.updateStats(result.stats.originalSize, result.stats.compressedSize);
            ui.showResultsSection();
            if (state.appSettings.autoCopyDecodedText) {                await ui.copyToClipboard(result.text, elements.copyBtn);
            }
            ui.showToast('تم فك تشفير النص بنجاح', 'success');
        }
    } catch (err) {
        if (err.message !== "Password required") {
            ui.showToast(`خطأ في فك التشفير: ${err.message}`, 'error');
        }
    }
}

async function decodeMessage(src) {
    const combinedData = crypto.decodeEmojiToBytes(src);
    if (combinedData.length === 0) throw new Error('لا توجد بيانات صالحة.');

    const { header, payloadBytes } = disassemblePayload(combinedData);
    if (!header || !payloadBytes) throw new Error('البيانات الوصفية تالفة أو غير معترفة.');

    let decryptedBytes = payloadBytes;
    if (header.enc) {
        const password = elements.password.value;
        if (!password) {
            ui.showToast('النص مشفر، يرجى إدخال كلمة السر', 'error');
            throw new Error("Password required");
        }
        decryptedBytes = await crypto.AdvancedEncryption.decrypt(
            payloadBytes, crypto.base64ToBytes(header.salt), crypto.base64ToBytes(header.iv), password, header.iter
        );
    }

    const finalText = header.comp
        ? crypto.AdvancedCompression.decompress(decryptedBytes)
        : crypto.getDecoder().decode(decryptedBytes);

    return {
        text: finalText,
        stats: { originalSize: header.origSize, compressedSize: header.compSize }
    };
}

function packPayloadV3(payloadBytes, origSize, compressed, encrypted, encResult = null) {
    const isComp = compressed ? 1 : 0;
    const isEnc = encrypted ? 1 : 0;
    const version = 3;
    const flags = (isComp & 0x01) | ((isEnc & 0x01) << 1) | ((version & 0x3F) << 2);

    let headerLength = 6;
    if (isEnc && encResult) {
        headerLength += 32 + 16 + 4;
    }

    const buffer = new Uint8Array(headerLength + payloadBytes.length);
    buffer[0] = 0xEC; // Magic byte 0xEC
    buffer[1] = flags;

    const view = new DataView(buffer.buffer);
    view.setUint32(2, origSize, false);

    let offset = 6;
    if (isEnc && encResult) {
        buffer.set(encResult.salt, offset);
        offset += 32;
        buffer.set(encResult.iv, offset);
        offset += 16;
        view.setUint32(offset, encResult.iterations, false);
        offset += 4;
    }

    buffer.set(payloadBytes, offset);
    return buffer;
}

function disassemblePayload(combinedData) {
    // 1. Try V3 Compact Binary Payload (starts with Magic Byte 0xEC)
    if (combinedData.length >= 6 && combinedData[0] === 0xEC) {
        const flags = combinedData[1];
        const isComp = Boolean(flags & 0x01);
        const isEnc = Boolean(flags & 0x02);
        const version = (flags >> 2) & 0x3F;

        const view = new DataView(combinedData.buffer, combinedData.byteOffset, combinedData.byteLength);
        const origSize = view.getUint32(2, false);

        let offset = 6;
        let salt = null;
        let iv = null;
        let iterations = 0;

        if (isEnc) {
            if (combinedData.length < 58) return {};
            salt = combinedData.slice(offset, offset + 32);
            offset += 32;
            iv = combinedData.slice(offset, offset + 16);
            offset += 16;
            iterations = view.getUint32(offset, false);
            offset += 4;
        }

        const payloadBytes = combinedData.slice(offset);
        return {
            header: {
                v: version,
                comp: isComp,
                enc: isEnc,
                origSize,
                compSize: payloadBytes.length,
                salt: salt ? crypto.bytesToBase64(salt) : '',
                iv: iv ? crypto.bytesToBase64(iv) : '',
                iter: iterations
            },
            payloadBytes
        };
    }

    // 2. Fallback to Legacy V2 Payload format (JSON header with HEADER_MARKER and SEPARATOR)
    const markerBytes = crypto.getEncoder().encode(HEADER_MARKER);
    const separatorBytes = crypto.getEncoder().encode(SEPARATOR);
    const headerStart = findSubarray(combinedData, markerBytes) + markerBytes.length;
    const separatorStart = findSubarray(combinedData, separatorBytes, headerStart);
    if (headerStart === markerBytes.length - 1 || separatorStart === -1) return {};
    const headerBytes = combinedData.slice(headerStart, separatorStart);
    const payloadBytes = combinedData.slice(separatorStart + separatorBytes.length);

    try {
        const header = JSON.parse(crypto.getDecoder().decode(headerBytes));
        return { header, payloadBytes };
    } catch {
        return {};
    }
}

function findSubarray(arr, sub, start = 0) {
    for (let i = start; i < arr.length - sub.length + 1; i++) {
        let found = true;
        for (let j = 0; j < sub.length; j++) {            if (arr[i + j] !== sub[j]) {
                found = false;
                break;
            }
        }
        if (found) return i;
    }
    return -1;
}

function getEncryptionIterations() {
    if (elements.useCustomIterations.checked) {
        const custom = parseInt(elements.customIterations.value, 10);
        if (custom >= 10000) return custom;
    }
    return { low: 50000, medium: 100000, high: 200000 }[state.appSettings.encryptionStrength] || 100000;
}

function addHistoryEntry(text, result) {
    if (!state.appSettings.saveHistory) return;
    state.historyItems.unshift({
        text: text.substring(0, 100),
        result,
        timestamp: new Date().toISOString(),
        operation: 'encode'
    });
    if (state.historyItems.length > 50) {
        state.historyItems = state.historyItems.slice(0, 50);
    }
    state.saveHistory();
    ui.renderHistory();
}
