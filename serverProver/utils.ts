import { gunzipSync } from 'zlib';
import { Barretenberg, RawBuffer, UltraHonkBackend, Fr } from "@aztec/bb.js";
import fs from 'fs';

/**
 * Convert data structure to TOML format
 * 
 * @param input - Object containing root, paths, and bad_hashes
 * @returns TOML formatted string
 */
export const toToml = (input: { 
    root: string; 
    paths: string[]; 
    bad_hashes: string[] 
}): string => {
    const lines = [];

    lines.push(`root = "${input.root}"\n`);

    lines.push("paths = [");
    for (const path of input.paths) {
        lines.push(`  "${path}",`);
    }
    lines.push("]\n");

    lines.push("bad_hashes = [");
    for (const hash of input.bad_hashes) {
        lines.push(`  "${hash}",`);
    }
    lines.push("]");

    return lines.join("\n");
};

/**
 * Read and decompress whitelist file
 * 
 * @param dumpFile - Path to compressed whitelist file
 * @returns Array of hex strings representing whitelisted memory regions
 */
export const readWhiteList = (dumpFile: string): string[] => {
    try {
        const compressedData = fs.readFileSync(dumpFile);
        const decompressed = gunzipSync(compressedData);

        const whitelistPath: string[] = [];
        for (let i = 0; i < decompressed.length; i += 32) {
            const chunk = decompressed.subarray(i, i + 32);
            whitelistPath.push("0x" + chunk.toString("hex"));
        }
        
        return whitelistPath;
    } catch (error) {
        console.error(`Error reading whitelist file ${dumpFile}:`, error);
        return [];
    }
};

/**
 * Build Merkle tree from array of field elements
 * 
 * @param api - Barretenberg API instance
 * @param path - Array of field elements to merkelize
 * @returns Root hash of the Merkle tree
 */
export const merkelize = async (api: Barretenberg, path: Fr[]): Promise<Fr> => {
    if (path.length === 0) {
        throw new Error("Cannot merkelize empty path");
    }
    
    let currentLevel: Fr[] = path;
    const depth = Math.log2(path.length);
    
    for (let i = 0; i < depth; i++) {
        let newLevel: Fr[] = [];
        
        for (let j = 0; j < currentLevel.length - 1; j += 2) {
            const hash: Fr = await api.poseidon2Hash([currentLevel[j], currentLevel[j + 1]] as Fr[]);
            newLevel.push(hash);
        }
        
        currentLevel = newLevel;
    }

    // Ensure we always return a valid Fr value
    if (currentLevel.length === 0 || !currentLevel[0]) {
        throw new Error("Merkelization failed - no root generated");
    }
    
    return currentLevel[0];
};

/**
 * Check current state against whitelist to detect unauthorized changes
 * 
 * @param whitelistPath - Array of whitelisted memory hashes
 * @param currentPath - Array of current memory hashes
 * @returns Number of differences found
 */
export const whitelist_check = async (whitelistPath: string[], currentPath: string[]): Promise<number> => {
    let differences = 0;
    
    for (let i = 0; i < whitelistPath.length; i += 1) {
        const whitelisted = whitelistPath[i];
        const current = currentPath[i];
        
        // Skip zero hashes (unused memory regions) and check for unauthorized changes
        if (whitelisted !== "0x0000000000000000000000000000000000000000000000000000000000000000" 
            && whitelisted !== current) {
            differences += 1;
        }
    }
    
    return differences;
};

/**
 * Convert Blake3 hashes to Poseidon field elements
 * 
 * @param api - Barretenberg API instance
 * @param hashes - Array of hex hash strings
 * @returns Array of field element strings
 */
export const blake3_to_poseidon = async (api: Barretenberg, hashes: string[]): Promise<string[]> => {
    try {
        const currentSlice: number[][] = hashes.map(hash => 
            Array.from(Buffer.from(hash?.slice(2), "hex"))
        );
        
        const currentLevel = await Promise.all(currentSlice.map(async (bytes: number[]) => {
            return await api.poseidon2Hash(bytes.map(byte => new Fr(BigInt(byte))));
        }));
        
        return currentLevel.map(field => field.toString());
    } catch (error) {
        console.error("Error converting Blake3 hashes to Poseidon:", error);
        return [];
    }
};