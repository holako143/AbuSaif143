import {
    ZERO_WIDTH_CHARS,
    VARIATION_SELECTOR_START,
    VARIATION_SELECTOR_END,
    VARIATION_SELECTOR_SUPPLEMENT_START,
    VARIATION_SELECTOR_SUPPLEMENT_END
} from './config.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: false, ignoreBOM: true });

const ZW_MAP = new Map(ZERO_WIDTH_CHARS.map((c, i) => [c, i]));

export function getEncoder() { return encoder; }
export function getDecoder() { return decoder; }

export function bytesToBase64(bytes) {
    let binString = '';
    for (let i = 0; i < bytes.length; i++) {
        binString += String.fromCharCode(bytes[i]);
    }
    return btoa(binString);
}

export function base64ToBytes(base64) {
    const binString = atob(base64);
    const bytes = new Uint8Array(binString.length);
    for (let i = 0; i < binString.length; i++) {
        bytes[i] = binString.charCodeAt(i);
    }
    return bytes;
}

/**
 * Encodes bytes into zero-width invisible characters appended to an emoji.
 * Base-8 representation using 8 zero-width characters (3 bits per character).
 */
export function encodeBytesToEmoji(emoji, bytes) {
    let bitString = '';
    for (let i = 0; i < bytes.length; i++) {
        bitString += bytes[i].toString(2).padStart(8, '0');
    }
    const remainder = bitString.length % 3;
    if (remainder !== 0) {
        bitString += '0'.repeat(3 - remainder);
    }

    let invisiblePayload = '';
    for (let i = 0; i < bitString.length; i += 3) {
        const val = parseInt(bitString.substring(i, i + 3), 2);
        invisiblePayload += ZERO_WIDTH_CHARS[val];
    }

    return emoji + invisiblePayload;
}

/**
 * Decodes zero-width invisible characters or legacy variation selectors from text back to Uint8Array.
 */
export function decodeEmojiToBytes(text) {
    // Check if text contains Zero-Width Characters first
    let bitString = '';
    for (const char of text) {
        if (ZW_MAP.has(char)) {
            const val = ZW_MAP.get(char);
            bitString += val.toString(2).padStart(3, '0');
        }
    }

    if (bitString.length >= 8) {
        const byteCount = Math.floor(bitString.length / 8);
        const bytes = new Uint8Array(byteCount);
        for (let i = 0; i < byteCount; i++) {
            bytes[i] = parseInt(bitString.substring(i * 8, i * 8 + 8), 2);
        }
        return bytes;
    }

    // Fallback: Legacy Variation Selector decoding
    return decodeLegacyEmojiToBytes(text);
}

function fromVariationSelector(codePoint) {
    if (codePoint >= VARIATION_SELECTOR_START && codePoint <= VARIATION_SELECTOR_END) {
        return codePoint - VARIATION_SELECTOR_START;
    } else if (codePoint >= VARIATION_SELECTOR_SUPPLEMENT_START && codePoint <= VARIATION_SELECTOR_SUPPLEMENT_END) {
        return codePoint - VARIATION_SELECTOR_SUPPLEMENT_START + 16;
    }
    return null;
}

function decodeLegacyEmojiToBytes(text) {
    let decoded = [];
    const chars = Array.from(text);
    let startIndex = 0;
    for (let i = 0; i < chars.length; i++) {
        const byte = fromVariationSelector(chars[i].codePointAt(0));
        if (byte === null) {
            startIndex = i + 1;
            break;
        }
    }
    for (let i = startIndex; i < chars.length; i++) {
        const char = chars[i];
        const byte = fromVariationSelector(char.codePointAt(0));
        if (byte !== null) {
            decoded.push(byte);
        } else {
            break;
        }
    }
    return new Uint8Array(decoded);
}

/**
 * Advanced Compression using LZ77 byte-stream compression algorithm.
 * Significantly compresses Arabic, English, and repeating character patterns.
 */
export class AdvancedCompression {
    static compress(text) {
        if (!text || text.length === 0) return new Uint8Array(0);
        try {
            const textBytes = encoder.encode(text);
            const lzCompressed = this.lz77Compress(textBytes);
            // Return compressed only if smaller, else uncompressed with flag
            if (lzCompressed.length < textBytes.length) {
                return lzCompressed;
            }
            return textBytes;
        } catch (error) {
            console.error('Compression error:', error);
            return encoder.encode(text);
        }
    }

    static decompress(data) {
        if (!data || data.length === 0) return '';
        try {
            const decompressed = this.lz77Decompress(data);
            return decoder.decode(decompressed);
        } catch (error) {
            console.error('Decompression error:', error);
            try {
                return decoder.decode(data);
            } catch (e) {
                console.error('Fallback decode error:', e);
                return '';
            }
        }
    }

    static lz77Compress(data) {
        const result = [];
        const windowSize = 255;
        const maxMatch = 255;
        let i = 0;

        while (i < data.length) {
            let matchLength = 0;
            let matchOffset = 0;

            const startWindow = Math.max(0, i - windowSize);
            for (let j = startWindow; j < i; j++) {
                let k = 0;
                while (i + k < data.length && k < maxMatch && data[j + k] === data[i + k]) {
                    k++;
                }
                if (k > matchLength) {
                    matchLength = k;
                    matchOffset = i - j;
                }
            }

            if (matchLength >= 3) {
                result.push(255, matchOffset, matchLength);
                i += matchLength;
            } else {
                if (data[i] === 255) {
                    result.push(255, 0, 0); // Escape literal 255 byte
                } else {
                    result.push(data[i]);
                }
                i++;
            }
        }
        return new Uint8Array(result);
    }

    static lz77Decompress(data) {
        const result = [];
        let i = 0;

        while (i < data.length) {
            if (data[i] === 255) {
                if (i + 2 >= data.length) break;
                const offset = data[i + 1];
                const length = data[i + 2];
                if (offset === 0 && length === 0) {
                    result.push(255);
                    i += 3;
                } else {
                    const startPos = result.length - offset;
                    for (let k = 0; k < length; k++) {
                        result.push(result[startPos + k]);
                    }
                    i += 3;
                }
            } else {
                result.push(data[i]);
                i++;
            }
        }
        return new Uint8Array(result);
    }
}

export class AdvancedEncryption {
    static async generateKey(password, salt, iterations) {
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            'PBKDF2',
            false,
            ['deriveKey']
        );
        return crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    static async encrypt(data, password, iterations) {
        const salt = crypto.getRandomValues(new Uint8Array(32));
        const iv = crypto.getRandomValues(new Uint8Array(16));
        const key = await this.generateKey(password, salt, iterations);
        const additionalData = encoder.encode('EmojiCipherPro-v3.0');
        const encryptedData = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv, additionalData },
            key,
            data
        );
        return {
            encrypted: new Uint8Array(encryptedData),
            salt: salt,
            iv: iv,
            iterations: iterations
        };
    }

    static async decrypt(encryptedData, salt, iv, password, iterations) {
        const key = await this.generateKey(password, salt, iterations);
        const additionalData = encoder.encode('EmojiCipherPro-v3.0');
        try {
            const decryptedData = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv, additionalData },
                key,
                encryptedData
            );
            return new Uint8Array(decryptedData);
        } catch (e) {
            // Fallback try legacy additionalData for v2 backward compatibility
            const legacyAdditionalData = encoder.encode('EmojiCipherPro-v2.1');
            const decryptedData = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv, additionalData: legacyAdditionalData },
                key,
                encryptedData
            );
            return new Uint8Array(decryptedData);
        }
    }
}

export class AdvancedCRC {
    static crc32Table = (() => {
        const table = new Uint32Array(256);
        for (let i = 0; i < 256; i++) {
            let c = i;
            for (let j = 0; j < 8; j++) {
                c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
            }
            table[i] = c;
        }
        return table;
    })();

    static calculate(str) {
        const bytes = encoder.encode(str);
        let crc = 0 ^ (-1);
        for (let i = 0; i < bytes.length; i++) {
            crc = (crc >>> 8) ^ this.crc32Table[(crc ^ bytes[i]) & 0xFF];
        }
        return (crc ^ (-1)) >>> 0;
    }
}
