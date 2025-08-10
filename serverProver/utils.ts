import { gunzipSync } from 'zlib';
import { Barretenberg, RawBuffer, UltraHonkBackend, Fr } from "@aztec/bb.js";
import fs from 'fs';

export const toToml = (input: { root: string; paths: string[]; bad_hashes: string[] }): string => {
    const lines = [];

    lines.push(`root = "${input.root}"\n`);

    lines.push("paths = [");
    for (const p of input.paths) {
        lines.push(`  "${p}",`);
    }
    lines.push("]\n");

    lines.push("bad_hashes = [");
    for (const h of input.bad_hashes) {
        lines.push(`  "${h}",`);
    }
    lines.push("]");

    return lines.join("\n");
}

export const readWhiteList = (dumpFile: string) => {
    const compressedData = fs.readFileSync(dumpFile);
    const decompressed = gunzipSync(compressedData);

    let whitelist_path = [];
    for (let i = 0; i < decompressed.length; i += 32) {
        whitelist_path.push("0x" + decompressed.subarray(i, i + 32).toString("hex"));
    }
    return whitelist_path;
}


export const merkelize = async (api: Barretenberg, path: Fr[]) => {
    let current_level: Fr[] = path;
    const depth = Math.log2(path.length);
    for (let i = 0; i < depth; i++) {
        let new_level: Fr[] = [];
        for (let j = 0; j < current_level.length - 1; j += 2) {
            const hash: Fr = await api.poseidon2Hash([current_level[j], current_level[j + 1]] as Fr[]);
            new_level.push(hash);
        }
        current_level = new_level;
    }


    return current_level[0];
}



export const whitelist_check = async (whitelist_path: string[], path: string[]) => {
    let diffs = 0;
    for (let i = 0; i < whitelist_path.length; i += 1) {
        if (whitelist_path[i] != "0x0000000000000000000000000000000000000000000000000000000000000000" && whitelist_path[i] != path[i]) {
            diffs += 1;
        }
    }
    return diffs
}

export const blake3_to_poseidon = async (api: Barretenberg, p: string[]) => {
    const current_slice: number[][] = p.map(x => Array.from(Buffer.from(x?.slice(2), "hex")))
    let current_level = await Promise.all(current_slice.map(async (x: number[]) => {
        return await api.poseidon2Hash(x.map(y => new Fr(BigInt(y))))
    }));
    return current_level.map(x => x.toString())
}