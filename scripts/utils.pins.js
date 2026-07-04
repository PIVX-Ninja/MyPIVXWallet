import { Buffer } from 'buffer';
import { sha256 } from '@noble/hashes/sha256';

export function bytesToHex(bytes) {
    return Buffer.from(bytes).toString('hex');
}

export const PIVXNameTLDs = ['.pivx', '.secure', '.safe', '.private'];

/**
 * Check if a domain string ends with one of the supported PIVX TLDs
 * @param {string} strDomain
 * @returns {boolean}
 */
export function isPIVXNameTLD(strDomain) {
    if (!strDomain) return false;
    const lower = strDomain.toLowerCase();
    return PIVXNameTLDs.some(tld => lower.endsWith(tld));
}

/**
 * Check if a string is a valid PIVX domain name (PiNS format)
 * @param {string} strDomain
 * @returns {boolean}
 */
export function isPIVXName(strDomain) {
    if (!strDomain) return false;
    const lower = strDomain.toLowerCase();
    
    // Find matching TLD
    const matchedTld = PIVXNameTLDs.find(tld => lower.endsWith(tld));
    if (!matchedTld) return false;
    
    // Extract label
    const label = lower.substring(0, lower.length - matchedTld.length);
    
    // Total domain length must be <= 64 characters
    if (strDomain.length > 64) return false;
    
    // Label length must be > 0
    if (label.length < 1) return false;
    
    // Check characters: lowercase alphanumeric + hyphens
    const regex = /^[a-z0-9-]+$/;
    if (!regex.test(label)) return false;
    
    // Hyphens: No leading, trailing, or consecutive
    if (label.startsWith('-') || label.endsWith('-') || label.includes('--')) return false;
    
    return true;
}

export function verifySmtProof(domainName, targetAddress, ownerPubkey, price, nonce, merkleProof, expectedRoot) {
    const keyHash = sha256(new TextEncoder().encode(domainName.toLowerCase()));
    const key = keyHash.slice(0, 16);

    const domainBuf = Buffer.from(domainName, 'utf-8');
    const pubkeyBuf = Buffer.from(ownerPubkey, 'hex');
    const addressBuf = Buffer.from(targetAddress, 'utf-8');
    
    const writeUInt64LE = (val) => {
        const buf = Buffer.alloc(8);
        let bigVal = BigInt(val);
        for (let i = 0; i < 8; i++) {
            buf[i] = Number(bigVal & 0xffn);
            bigVal >>= 8n;
        }
        return buf;
    };
    const priceBuf = writeUInt64LE(price);
    const nonceBuf = writeUInt64LE(nonce);

    const leafData = Buffer.concat([domainBuf, pubkeyBuf, addressBuf, priceBuf, nonceBuf]);
    let current = sha256(leafData);

    const getBit = (bytes, bitIdx) => {
        const bytePos = Math.floor(bitIdx / 8);
        const bitPos = 7 - (bitIdx % 8);
        return (bytes[bytePos] >> bitPos) & 1;
    };

    for (let i = 0; i < 128; i++) {
        const sibling = Buffer.from(merkleProof[i], 'hex');
        const bitIdx = 127 - i;
        const bit = getBit(key, bitIdx);

        let combined;
        if (bit === 1) {
            combined = Buffer.concat([sibling, current]);
        } else {
            combined = Buffer.concat([current, sibling]);
        }
        current = sha256(combined);
    }

    return bytesToHex(current) === expectedRoot.toLowerCase();
}

export async function fetchArbitrumRoot(rpcUrl, contractAddress) {
    const payload = {
        jsonrpc: '2.0',
        method: 'eth_call',
        params: [
            {
                to: contractAddress,
                data: '0xfdab463d' // selector for currentRoot()
            },
            'latest'
        ],
        id: 1
    };
    
    const response = await fetch(rpcUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
    });
    
    if (!response.ok) {
        throw new Error(`Failed to fetch EVM root: ${response.statusText}`);
    }
    
    const data = await response.json();
    if (data.error) {
        throw new Error(`EVM RPC error: ${data.error.message}`);
    }
    
    const hexResult = data.result;
    if (!hexResult || hexResult === '0x') {
        throw new Error('EVM RPC returned empty result');
    }
    return hexResult.replace(/^0x/, '').toLowerCase();
}

export async function fetchIndexerRoot(apiEndpoint) {
    const res = await fetch(`${apiEndpoint.replace(/\/$/, '')}/v1.0/info`);
    if (!res.ok) {
        throw new Error(`Indexer info responded with status ${res.status}`);
    }
    const data = await res.json();
    if (!data || !data.response || !data.response.indexer_smt_root) {
        throw new Error("Invalid response from indexer info");
    }
    return data.response.indexer_smt_root.toLowerCase();
}

export async function verifyRootValidityOnContract(rpcUrl, contractAddress, smtRoot) {
    if (!smtRoot) return false;
    // 66dd97ab is the selector for rootHistory(bytes32)
    const cleanRoot = smtRoot.replace(/^0x/, '').toLowerCase();
    const payload = {
        jsonrpc: '2.0',
        method: 'eth_call',
        params: [
            {
                to: contractAddress,
                data: `0x66dd97ab${cleanRoot.padStart(64, '0')}`
            },
            'latest'
        ],
        id: 1
    };
    
    const response = await fetch(rpcUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
    });
    
    if (!response.ok) {
        throw new Error(`Failed to fetch root history: ${response.statusText}`);
    }
    
    const data = await response.json();
    if (data.error) {
        throw new Error(`EVM RPC error: ${data.error.message}`);
    }
    
    const hexResult = data.result;
    if (!hexResult || hexResult === '0x') {
        throw new Error('EVM RPC returned empty result');
    }
    
    // Check if the result is true (0x000000...0001) or false (0x000000...0000)
    const intResult = BigInt(hexResult);
    return intResult !== 0n;
}

