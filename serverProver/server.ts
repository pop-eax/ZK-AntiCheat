import { Barretenberg, RawBuffer, UltraHonkBackend, Fr } from "@aztec/bb.js";
import innerCircuit from "../circuits/merkleProof/target/merkleproof.json" assert { type: "json" };
import recursiveCircuit from "../circuits/gamePlayProver/target/gamePlayProver.json" assert { type: "json" };
import whitelistCircuit from "../circuits/whitelist/target/whitelist.json" assert { type: "json" };
import recursiveWhitelistCircuit from "../circuits/recursiveWhitelist/target/recursiveWhitelist.json" assert { type: "json" };
import commitRevealCircuit from "../circuits/commitReveal/target/commitReveal.json" assert {type: "json" };
import { type CompiledCircuit, Noir } from "@noir-lang/noir_js";
import { merkelize, whitelist_check, readWhiteList, blake3_to_poseidon, toToml } from "./utils";
import express from "express";
import fs from 'fs';

const app = express();
const port = 9000;
app.use(express.json({ limit: '20mb' }));

const PATH_LENGTH = 4096;
const PROOF_ACCUMLATION = 10;
const aggregate = false;

interface CommitRevealInputs {
    hash: number[],
    segment: string[],
    indices: string[],
    values: number[]
}

interface QueueObject {
    type: string;
    root?: string;
    path?: string[][];
    reveal?: CommitRevealInputs;

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
let whitelistCheck = true;
let accumulator = Fr.ZERO;
let provedRoots: string[] = [];
let accumulatedProofs: any = { pub_inputs: [], proofs: [] };

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
async function generateProof(hexRoot: string, path: string[]): Promise<void> {
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
                //fix the null values
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
                    await backends.whitelistBackend.generateProof(witness);

                const innerCircuitVerificationKey = await backends.whitelistBackend.getVerificationKey();
                const vkAsFields = (await api.acirVkAsFieldsUltraHonk(new RawBuffer(innerCircuitVerificationKey)))
                    .map(field => field.toString());

                const recursiveInputs = {
                    proof: innerProofFields,
                    public_inputs: innerPublicInputs,
                    verification_key: vkAsFields
                };

                // const { witness: recursiveWitness } = await circuits.recursiveWhitelist.execute(recursiveInputs);
                // const { proof: recursiveProof, publicInputs: recursivePublicInputs } =
                //     await backends.recursiveWhitelist.generateProof(recursiveWitness);

                console.log("Whitelist validation proof generated successfully");
                whitelistCheck = false;
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
                await backends.main.generateProof(witness);

            // Get verification key for inner circuit as fields
            const innerCircuitVerificationKey = await backends.main.getVerificationKey();


            // accumulatedProofs.pub_inputs.push(innerPublicInputs);
            // accumulatedProofs.proofs.push(innerProofFields);

            // Generate recursive proof

            if (aggregate && accumulatedProofs.proofs.length >= PROOF_ACCUMLATION) {
                console.log("Starting aggregation");
                let newRoot = accumulator;
                for (let i = 0; i < PROOF_ACCUMLATION; i++) {
                    newRoot = await api.poseidon2Hash([newRoot, Fr.fromString(accumulatedProofs.pub_inputs[i][0])]);
                }
                const vkAsFields = (await api.acirVkAsFieldsUltraHonk(new RawBuffer(innerCircuitVerificationKey)))
                    .map(field => field.toString());
                const recursiveInputs = {
                    proof1: accumulatedProofs.proofs[0], //.slice(0, PROOF_ACCUMLATION)
                    public_inputs1: accumulatedProofs.pub_inputs[0],
                    proof2: accumulatedProofs.proofs[1],
                    public_inputs2: accumulatedProofs.pub_inputs[1],
                    verification_key: vkAsFields,
                    accumulator: accumulator.toString(),
                    new_root: newRoot.toString()
                };

                const { witness: recursiveWitness } = await circuits.recursiveCircuit.execute(recursiveInputs);
                const { proof: recursiveProof, publicInputs: recursivePublicInputs } = await backends.recursiveBackend.generateProof(recursiveWitness);

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

                accumulatedProofs.proofs = accumulatedProofs.proofs.slice(10);
                accumulatedProofs.pub_inputs = accumulatedProofs.pub_inputs.slice(10);

            } else {
                accumulator = await api.poseidon2Hash([accumulator, Fr.fromString(innerPublicInputs[0] as string)]);
                console.log(`Inner proof generation done with new state root: ${accumulator}`);
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



async function commitReveal(ins: CommitRevealInputs) {
    const circuit = new Noir(commitRevealCircuit as CompiledCircuit);
    const backend = new UltraHonkBackend(commitRevealCircuit.bytecode, { threads: 0 });
    // const inputs = {
    //     hash: 
    //     segment: ins.segment,
    //     indices: ins.indices,
    //     values: ins.values,

    // }
    // console.log(inputs);
    const { witness } = await circuit.execute(ins as any);
    const { proof: innerProofFields, publicInputs: innerPublicInputs } = await backend.generateProof(witness);
    console.log(`Revealed the score value: ${ins.values[2]?.toString(16)+ins.values[1]?.toString(16)+ins.values[0]?.toString(16)}`);
}

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

    while (!isProcessing && queue.length > 0) {
        isProcessing = true;

        try {
            console.log("Processing started at:", new Date().toLocaleTimeString());
            console.log(`Queued elements: ${queue.length}`);

            let data: QueueObject = queue.pop() as QueueObject;
            if (data.type == "general") {
                for (let i = 0; i < (data.path as string[][]).length; i += 1) {
                    await generateProof(data.root as string, (data.path as string[][])[i] as string[]);
                }
            }else if (data.type == "reveal") {
                await commitReveal(data.reveal as CommitRevealInputs);
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
    queue.push({
        type: "general",
        root: req.body["root"],
        path: req.body["path"],
    });
    res.status(200).send('Data received successfully');
});

app.post("/reveal", (req: any, res: any) => {
    console.log("New reveal request received.");
    queue.push({
        type: "reveal",
        reveal: {
            segment: req.body["segment"],
            hash: Array.from(Buffer.from(req.body["hash"], "hex")),
            values: req.body["values"],
            indices: req.body["indices"]
        }
    });
    res.status(200).send("Done.");
})

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
