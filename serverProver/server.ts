import { Barretenberg, RawBuffer, UltraHonkBackend, Fr } from "@aztec/bb.js";
import innerCircuit from "../circuits/merkleProof/target/merkleproof.json" assert { type: "json" };
import recursiveCircuit from "../circuits/gamePlayProver/target/gamePlayProver.json" assert { type: "json" };
import whitelistCircuit from "../circuits/whitelist/target/whitelist.json" assert { type: "json" };
import recursiveWhitelistCircuit from "../circuits/recursiveWhitelist/target/recursiveWhitelist.json" assert { type: "json" };
import { type CompiledCircuit, Noir } from "@noir-lang/noir_js";
import { merkelize, whitelist_check, readWhiteList, blake3_to_poseidon, toToml } from "./utils";
import express from "express";
import fs from 'fs';

const app = express();
const port = 9000;
app.use(express.json({ limit: '20mb' }));

const PATH_LENGTH = 4096;

interface QueueObject {
    root: string;
    path: string[][];
}

interface CircuitInstances {
    main: Noir;
    recursiveCircuit: Noir;
    whitelistCircuit: Noir;
    recursiveWhitelist: Noir;
}

interface BackendInstances {
    main: UltraHonkBackend;
    recursiveBackend: UltraHonkBackend;
    whitelistBackend: UltraHonkBackend;
    recursiveWhitelist: UltraHonkBackend;
}

// Configuration flags
let whitelistCheck = false;
let accumulator = Fr.ZERO;
let provedRoots: string[] = [];

/**
 * Generate proof of game state validity
 * 
 * This function processes game state data and generates ZK proofs to verify:
 * - Memory integrity against whitelist
 * - State transitions
 * - Recursive proof aggregation
 * 
 * @param hexRoot - Root hash of the game state
 * @param path - Array of memory paths to validate
 */
const generateProof = async (hexRoot: string, path: string[]): Promise<void> => {
    const whitelist = readWhiteList("./static_memory_nes.bin");

    // Initialize circuit instances
    const circuits: CircuitInstances = {
        main: new Noir(innerCircuit as CompiledCircuit),
        recursiveCircuit: new Noir(recursiveCircuit as CompiledCircuit),
        whitelistCircuit: new Noir(whitelistCircuit as CompiledCircuit),
        recursiveWhitelist: new Noir(recursiveWhitelistCircuit as CompiledCircuit)
    };

    // Initialize backend instances
    const backends: BackendInstances = {
        main: new UltraHonkBackend(innerCircuit.bytecode, { threads: 0 }, { recursive: true }),
        recursiveBackend: new UltraHonkBackend(recursiveCircuit.bytecode, { threads: 0 }),
        whitelistBackend: new UltraHonkBackend(whitelistCircuit.bytecode, { threads: 0 }, { recursive: true }),
        recursiveWhitelist: new UltraHonkBackend(recursiveWhitelistCircuit.bytecode, { threads: 0 })
    };

    const api = await Barretenberg.new({ threads: 1 });

    try {
        // Convert hex strings to field elements
        const currentSlice: number[][] = path.map(x => Array.from(Buffer.from(x?.slice(2), "hex")));
        let currentLevel = await Promise.all(currentSlice.map(async (x: number[]) => {
            return await api.poseidon2Hash(x.map(y => new Fr(BigInt(y))));
        }));
        
        let leaves = currentLevel.map(x => x.toString());
        const rootFr: Fr = await merkelize(api, currentLevel) as Fr;
        const root = rootFr?.toString() as string;

        if (whitelistCheck) {
            // Process whitelist validation
            const inputs = {
                whitelisted: (await blake3_to_poseidon(api, whitelist)).map(elem => 
                    elem === "0x2a5aabd2497e5a28f96c54488d4d81df11fabe139a01b4205f04ff3f61ffbfd2" 
                        ? "0x0000000000000000000000000000000000000000000000000000000000000000" 
                        : elem
                ),
                currentState: leaves,
                hash: root
            };

            const diffs = await whitelist_check(inputs.whitelisted, inputs.currentState);
            if (diffs === 0) {
                const { witness } = await circuits.whitelistCircuit.execute(inputs);
                const { proof: innerProofFields, publicInputs: innerPublicInputs } = 
                    await backends.whitelistBackend.generateProofForRecursiveAggregation(witness);

                const innerCircuitVerificationKey = await backends.whitelistBackend.getVerificationKey();
                const vkAsFields = (await api.acirVkAsFieldsUltraHonk(new RawBuffer(innerCircuitVerificationKey)))
                    .map(field => field.toString());

                const recursiveInputs = { 
                    proof: innerProofFields, 
                    public_inputs: innerPublicInputs, 
                    verification_key: vkAsFields 
                };
                
                const { witness: recursiveWitness } = await circuits.recursiveWhitelist.execute(recursiveInputs);
                const { proof: recursiveProof, publicInputs: recursivePublicInputs } = 
                    await backends.recursiveWhitelist.generateProof(recursiveWitness);
                
                console.log("Whitelist validation proof generated successfully");
            }
        } else if (provedRoots.includes(root)) {
            console.log("Root is already proven, updating accumulator");
            accumulator = await api.poseidon2Hash([rootFr, accumulator]);
        } else {
            // Process new game state proof
            const badHash = "0x1c26e8b6bd7085688b4a932fc0638fa2e8962d2177bf3d89bb45b1189a5dbc77";
            const badHashIndex = path.findIndex((v) => v === badHash);

            let inputs: any;
            if (badHashIndex === -1) {
                inputs = { root: root, paths: leaves, bad_hashes: [badHash] };
            } else {
                console.log("Evil hash detected at index:", badHashIndex);
                inputs = { root: hexRoot, paths: leaves, bad_hashes: [badHash] };
            }

            const { witness } = await circuits.main.execute(inputs);
            const { proof: innerProofFields, publicInputs: innerPublicInputs } = 
                await backends.main.generateProofForRecursiveAggregation(witness);

            // Get verification key for inner circuit as fields
            const innerCircuitVerificationKey = await backends.main.getVerificationKey();
            const vkAsFields = (await api.acirVkAsFieldsUltraHonk(new RawBuffer(innerCircuitVerificationKey)))
                .map(field => field.toString());

            // Generate recursive proof
            let newRoot = await api.poseidon2Hash([rootFr, accumulator]);
            const recursiveInputs = { 
                proof: innerProofFields, 
                public_inputs: innerPublicInputs, 
                verification_key: vkAsFields, 
                accumulator: accumulator.toString(), 
                new_root: newRoot.toString() 
            };
            
            const { witness: recursiveWitness } = await circuits.recursiveCircuit.execute(recursiveInputs);
            const { proof: recursiveProof, publicInputs: recursivePublicInputs } = 
                await backends.recursiveBackend.generateProof(recursiveWitness);

            // Verify recursive proof
            const verified = await backends.recursiveBackend.verifyProof({ 
                proof: recursiveProof, 
                publicInputs: recursivePublicInputs 
            });
            
            if (verified) {
                provedRoots.push(root);
                accumulator = newRoot;
                console.log("Recursive proof verified successfully");
            } else {
                console.log("Recursive proof verification failed");
            }
        }
    } catch (error) {
        console.error("Error during proof generation:", error);
    } finally {
        // Cleanup resources
        await api.destroy();
        await backends.main.destroy();
        await backends.recursiveBackend.destroy();
        await backends.whitelistBackend.destroy();
        await backends.recursiveWhitelist.destroy();
    }
};

let queue: QueueObject[] = [];
let isProcessing = false;

/**
 * Process the proof generation queue
 * 
 * This function processes queued proof requests sequentially to avoid
 * overwhelming the ZK proof generation system.
 */
async function processQueue(): Promise<void> {
    console.log("Waiting for proof requests...");
    
    if (!isProcessing && queue.length > 0) {
        isProcessing = true;

        try {
            console.log("Processing started at:", new Date().toLocaleTimeString());
            console.log(`Queued elements: ${queue.length}`);
            
            let data: QueueObject = queue.pop() as QueueObject;
            for (let i = 0; i < data.path.length; i += 1) {
                await generateProof(data.root, data.path[i] as string[]);
            }

            console.log("Processing completed at:", new Date().toLocaleTimeString());
            console.log("New state root:", accumulator.toString());
        } catch (error) {
            console.error("Error during processing:", error);
        } finally {
            isProcessing = false;
        }
    }
    
    // Schedule next queue check
    setTimeout(processQueue, 15000);
}

// Start the queue processor
processQueue();

// API endpoint to receive game state data
app.post("/", (req: any, res: any) => {
    console.log(`New game play received: ${req.body["root"]}`);
    queue.push({ root: req.body["root"], path: req.body["path"] });
    res.status(200).send('Data received successfully');
});

// Health check endpoint
app.get("/health", (req: any, res: any) => {
    res.status(200).json({
        status: "healthy",
        queueLength: queue.length,
        isProcessing: isProcessing,
        provedRootsCount: provedRoots.length,
        accumulator: accumulator.toString()
    });
});

app.listen(port, () => {
    console.log(`🚀 Fairfy ZK Prover Server listening on port ${port}...`);
    console.log(`📊 Health check: http://localhost:${port}/health`);
    console.log(`🎮 Game state endpoint: POST http://localhost:${port}/`);
});
