import { Barretenberg, RawBuffer, UltraHonkBackend, Fr } from "@aztec/bb.js";
import innerCircuit from "../circuits/merkleProof/target/merkleproof.json" assert { type: "json" };
import recursiveCircuit from "../circuits/gamePlayProver/target/gamePlayProver.json" assert { type: "json" };
import whitelistCircuit from "../circuits/whitelist/target/whitelist.json" assert { type: "json" };
import recursvieWhitelistCircuit from "../circuits/recursiveWhitelist/target/recursiveWhitelist.json" assert { type: "json" };
import { type CompiledCircuit, Noir } from "@noir-lang/noir_js";
import { merkelize, whitelist_check, readWhiteList, blake3_to_poseidon, toToml } from "./utils";
import express from "express";
import fs from 'fs';


const app = express();
const port = 9000;
app.use(express.json({ limit: '20mb' }));

const PATH_LENGTH = 4096;

interface QueueObject {
    root: string,
    path: string[][]
}

let whitelistCheck = true;
let accumlator = Fr.ZERO;
let proved_roots: string[] = [];

/*
* Check all elements and make sure the static/bounded parts are valid or wihtin reach
* for the dynamic parts recursively go down the tree until we reach a whitelisted element
* if no whitelisted elements we are left with 2 possiblties either the element is blacklisted or undefined in case of undefined behavior it depends on the element position in memory
* critical parts have to be bounded by the whitelist so discrepancies aren't tolearted in more generic areas we can keep a note of it but it doesn't directly imply an invalid state
* Afterwards we are left with a state machine model where we only check the dynamic changing parts of memory where we can keep checking the deltas of states
* in some cases we might want to reveal the contents of the leaf to make sure it's within the bounds.
* the given input has to be signed by the user in order to prevent against 
* you can give me the proofs of inclusion outside of the circuit
*/
const proveit = async (hexRoot: string, p: string[]) => {
    const whitelist = readWhiteList("./static_memory_nes.bin")





    const circuits = {
        main: new Noir(innerCircuit as CompiledCircuit),
        recursiveCircuit: new Noir(recursiveCircuit as CompiledCircuit),
        whitelistCircuit: new Noir(whitelistCircuit as CompiledCircuit),
        recursiveWhiteList: new Noir(recursvieWhitelistCircuit as CompiledCircuit)
    };

    const backends = {
        main: new UltraHonkBackend(innerCircuit.bytecode, { threads: 0 }, { recursive: true }),
        recursiveBackend: new UltraHonkBackend(recursiveCircuit.bytecode, { threads: 0 }),
        whitelistBackend: new UltraHonkBackend(whitelistCircuit.bytecode, { threads: 0 }, { recursive: true }),
        recursiveWhiteList: new UltraHonkBackend(recursvieWhitelistCircuit.bytecode, { threads: 0 })
    };

    const api = await Barretenberg.new({ threads: 1 });

    const current_slice: number[][] = p.map(x => Array.from(Buffer.from(x?.slice(2), "hex")));
    let current_level = await Promise.all(current_slice.map(async (x: number[]) => {
        return await api.poseidon2Hash(x.map(y => new Fr(BigInt(y))));
    }));
    let leaves = current_level.map(x => x.toString());
    const rootFr: Fr = await merkelize(api, current_level) as Fr;
    const root = rootFr?.toString() as string

    try {

        if (whitelistCheck) {
            const inputs: any = {
                whitelisted: (await blake3_to_poseidon(api, whitelist)).map(elem => elem == "0x2a5aabd2497e5a28f96c54488d4d81df11fabe139a01b4205f04ff3f61ffbfd2" ? "0x0000000000000000000000000000000000000000000000000000000000000000" : elem),
                currentState: leaves,
                hash: root
            };

            const diffs = await whitelist_check(inputs.whitelisted, inputs.currentState);
            if (diffs == 0) {
                const { witness } = await circuits.whitelistCircuit.execute(inputs);
                const { proof: innerProofFields, publicInputs: innerPublicInputs } = await backends.whitelistBackend.generateProofForRecursiveAggregation(witness);

                const innerCircuitVerificationKey = await backends.whitelistBackend.getVerificationKey();
                const vkAsFields = (await api.acirVkAsFieldsUltraHonk(new RawBuffer(innerCircuitVerificationKey))).map(field => field.toString());

                const recursiveInputs = { proof: innerProofFields, public_inputs: innerPublicInputs, verification_key: vkAsFields };
                const { witness: recursiveWitness } = await circuits.recursiveWhiteList.execute(recursiveInputs);
                const { proof: recursiveProof, publicInputs: recursivePublicInputs } = await backends.recursiveWhiteList.generateProof(recursiveWitness);
                console.log("DONE");
            }
        }
        else if (proved_roots.includes(root)) {
            console.log("Root is already proven");
            accumlator = await api.poseidon2Hash([rootFr, accumlator]);
        } else {
            const bad_hash = "0x1c26e8b6bd7085688b4a932fc0638fa2e8962d2177bf3d89bb45b1189a5dbc77"
            const idx = p.findIndex((v) => v === bad_hash);

            let inputs: any;
            if (idx == -1) {
                inputs = { root: root, paths: leaves, bad_hashes: [bad_hash] };

            } else {
                console.log("Evil hash detected at:", idx);
                inputs = { root: hexRoot, paths: leaves, bad_hashes: [bad_hash] };
            }
            // fs.writeFileSync("input.toml", toToml(inputs));

            const { witness } = await circuits.main.execute(inputs);

            const { proof: innerProofFields, publicInputs: innerPublicInputs } = await backends.main.generateProofForRecursiveAggregation(witness);

            // Get verification key for inner circuit as fields
            const innerCircuitVerificationKey = await backends.main.getVerificationKey();
            const vkAsFields = (await api.acirVkAsFieldsUltraHonk(new RawBuffer(innerCircuitVerificationKey))).map(field => field.toString());

            // Generate proof of the recursive circuit

            let new_root = await api.poseidon2Hash([rootFr, accumlator]);
            const recursiveInputs = { proof: innerProofFields, public_inputs: innerPublicInputs, verification_key: vkAsFields, accumlator: accumlator.toString(), new_root: new_root.toString() };
            const { witness: recursiveWitness } = await circuits.recursiveCircuit.execute(recursiveInputs);
            const { proof: recursiveProof, publicInputs: recursivePublicInputs } = await backends.recursiveBackend.generateProof(recursiveWitness);

            // Verify recursive proof
            const verified = await backends.recursiveBackend.verifyProof({ proof: recursiveProof, publicInputs: recursivePublicInputs });
            if (verified) {
                proved_roots.push(root);
                accumlator = new_root;
            }
            console.log("Recursive proof verified: ", verified);
        }

        // let root = Array.from(Buffer.from(hexRoot, "hex"));
        // const bad_hash = Array.from(Buffer.from("1c26e8babd7085688b4a932fc0638fa2e8962d2177bf3d89bb45b1189a5dbc77", "hex"));


    } catch (error) {
        console.error(error);
    }
    await api.destroy();
    await backends.main.destroy();
    await backends.recursiveBackend.destroy();
};


let queue: QueueObject[] = [];
let proving = false;
async function processQueue() {
    console.log("Waiting...");
    if (!proving && queue.length > 0) {

        proving = true;

        try {
            console.log("Processing started at:", new Date().toLocaleTimeString());
            console.log(`Queued elements: ${queue.length}`);
            let data: QueueObject = queue.pop() as QueueObject;
            for (let i = 0; i < data.path.length; i += 1) {
                await proveit(data.root, data.path[i] as string[]);
            }

            console.log("Processing completed at:", new Date().toLocaleTimeString());
            console.log("New state root: ", accumlator.toString());
        } catch (error) {
            console.error("Error during processing:", error);
        } finally {
            proving = false;
        }
    }
    setTimeout(processQueue, 15000);
}

// Start the first execution
processQueue();

app.post("/", (req: any, res: any) => {
    console.log(`New game play received: ${req.body["root"]}`);
    queue.push({ root: req.body["root"], path: req.body["path"] });
    res.status(200).send('Data received successfully');

});


app.listen(port, () => {
    console.log(`Listening on port ${port}...`);
});
