<script setup>
import { ref } from 'vue';
import { Database } from '../database.js';
import { createAlert } from '../alerts/alert.js';
import { isShieldAddress } from '../misc.js';
import { 
    fetchArbitrumRoot, 
    fetchIndexerRoot, 
    verifyRootValidityOnContract,
    verifySmtProof
} from '../utils.pins.js';

// Events we can emit
const emit = defineEmits(['send']);

// Reactive States
const showSyncModal = ref(false);
const syncModalState = ref('warning');
const syncModalTitle = ref('⚠️ Indexer Sync Delay');
const syncModalText = ref('');
const syncModalConfirmText = ref('Send anyway');
const syncModalCancelText = ref('Cancel');
const syncModalIsPolling = ref(false);
const pendingSendParams = ref(null);

let syncModalInterval = null;

async function resolveDomainName(apiEndpoint, domain) {
    const res = await fetch(`${apiEndpoint.replace(/\/$/, '')}/v1.0/resolve/${domain}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({})
    });

    let json = null;
    try {
        json = await res.json();
    } catch (e) {
        // Not a JSON response
    }

    if (json && json.error) {
        const errMsg = json.error.error_message;
        if (errMsg === 'Domain not found') {
            return { isNotFound: true, resolveData: null };
        }
        throw new Error(errMsg);
    }

    if (!res.ok) {
        throw new Error(`Indexer responded with status ${res.status}`);
    }

    if (json && json.response) {
        return { isNotFound: false, resolveData: json.response };
    }

    throw new Error("Invalid response format from indexer");
}

async function getPivxNameRoots(apiEndpoint, strDomain, evmRpc, evmContractAddress) {
    let resolveData = null;
    let isNotFound = false;
    let indexerRoot = null;
    try {
        const res = await resolveDomainName(apiEndpoint, strDomain);
        isNotFound = res.isNotFound;
        if (!isNotFound) {
            resolveData = res.resolveData;
            indexerRoot = resolveData.smt_root;
        }
    } catch (e) {
        if (e.message === 'Domain not found') {
            isNotFound = true;
        } else {
            throw e;
        }
    }

    const evmRoot = await fetchArbitrumRoot(evmRpc, evmContractAddress);

    if (isNotFound) {
        indexerRoot = await fetchIndexerRoot(apiEndpoint);
    }

    const rootsMatch = evmRoot.toLowerCase() === indexerRoot.toLowerCase();

    return { rootsMatch, evmRoot, indexerRoot, isNotFound, resolveData };
}

function verifyResolvedDetails(strDomain, resolveData) {
    if (!resolveData) return false;
    const resolvedAddress = resolveData.target_address;
    const ownerPubkey = resolveData.owner_pubkey;
    const price = resolveData.price;
    const nonce = resolveData.nonce;
    const smtRoot = resolveData.smt_root;
    const merkleProof = resolveData.merkle_proof;

    if (!resolvedAddress || !ownerPubkey || price === undefined || nonce === undefined || !merkleProof || !smtRoot) {
        createAlert('warning', `Domain name ${strDomain} response metadata is incomplete or invalid.`, 5000);
        return false;
    }

    if (!verifySmtProof(strDomain, resolvedAddress, ownerPubkey, price, nonce, merkleProof, smtRoot)) {
        createAlert('warning', `Cryptographic verification of the name resolution failed: Merkle proof is invalid.`, 5000);
        return false;
    }

    if (!isShieldAddress(resolvedAddress)) {
        createAlert('warning', `Resolved address is not a valid shield address.`, 5000);
        return false;
    }

    if (resolveData.domain_name !== strDomain) {
        createAlert('warning', `Resolved name does not match requested name.`, 5000);
        return false;
    }

    return true;
}

function startSyncModalPolling(apiEndpoint, strDomain, evmRpc, evmContractAddress) {
    stopSyncModalPolling();
    syncModalIsPolling.value = true;
    
    syncModalInterval = setInterval(async () => {
        try {
            const { rootsMatch, isNotFound, resolveData } = await getPivxNameRoots(apiEndpoint, strDomain, evmRpc, evmContractAddress);
            
            if (rootsMatch) {
                stopSyncModalPolling();
                
                if (!isNotFound && resolveData && resolveData.target_address) {
                    if (pendingSendParams.value) {
                        pendingSendParams.value.address = resolveData.target_address;
                        pendingSendParams.value.resolveData = resolveData;
                    }
                    syncModalState.value = 'synced';
                    syncModalTitle.value = '✓ Synced & Resolved';
                    syncModalText.value = "The indexer is synced, ready and the name has been successfully resolved. You are safe to send your funds.";
                    syncModalConfirmText.value = 'Send';
                } else {
                    syncModalState.value = 'not_found_synced_error';
                    syncModalTitle.value = '❌ Domain Not Found';
                    syncModalText.value = "This domain name does not exist. Please check the spelling.";
                }
            }
        } catch (e) {
            console.error("Sync modal background check error:", e);
        }
    }, 5000);
}

function stopSyncModalPolling() {
    syncModalIsPolling.value = false;
    if (syncModalInterval) {
        clearInterval(syncModalInterval);
        syncModalInterval = null;
    }
}

function closeSyncModal(confirm) {
    stopSyncModalPolling();
    showSyncModal.value = false;
    
    if (confirm && pendingSendParams.value) {
        const { address, amount, useShieldInputs, memo, originalDomain, resolveData } = pendingSendParams.value;
        pendingSendParams.value = null;
        
        if (verifyResolvedDetails(originalDomain, resolveData)) {
            emit('send', { address, amount, useShieldInputs, memo });
        }
    } else {
        pendingSendParams.value = null;
    }
}

async function retrySyncModalResolution() {
    if (!showSyncModal.value || syncModalState.value !== 'not_found') return;
    
    const database = await Database.getInstance();
    const { nameResolvingApi, evmRpc, evmContractAddress } = await database.getSettings();
    const apiEndpoint = nameResolvingApi || 'https://indexer.pivx.name';
    
    stopSyncModalPolling();
    
    const checkingAlert = createAlert('info', `Checking sync status...`, 5000);
    try {
        const { rootsMatch, isNotFound, resolveData } = await getPivxNameRoots(apiEndpoint, pendingSendParams.value.originalDomain, evmRpc, evmContractAddress);
        
        if (checkingAlert) checkingAlert.close();
        if (rootsMatch) {
            stopSyncModalPolling();
            if (!isNotFound && resolveData) {
                showSyncModal.value = false;
                if (verifyResolvedDetails(pendingSendParams.value.originalDomain, resolveData)) {
                    emit('send', { 
                        address: resolveData.target_address, 
                        amount: pendingSendParams.value.amount, 
                        useShieldInputs: pendingSendParams.value.useShieldInputs, 
                        memo: pendingSendParams.value.memo 
                    });
                }
            } else {
                showSyncModal.value = false;
                createAlert('warning', `Domain name ${pendingSendParams.value.originalDomain} could not be resolved.`, 5000);
            }
        } else {
            createAlert('warning', 'Indexer is still syncing, please wait...', 3000);
            startSyncModalPolling(apiEndpoint, pendingSendParams.value.originalDomain, evmRpc, evmContractAddress);
        }
    } catch (e) {
        if (checkingAlert) checkingAlert.close();
        createAlert('warning', `Failed to check sync status: ${e.message || e}`, 3000);
    }
}

async function resolveAndVerify(domain, amount, useShieldInputs, memo) {
    const strDomain = domain.toLowerCase();
    const resolvingAlert = createAlert('info', `Resolving domain name ${strDomain}...`, 10000);
    
    try {
        const database = await Database.getInstance();
        const { nameResolvingApi, evmRpc, evmContractAddress } = await database.getSettings();
        const apiEndpoint = nameResolvingApi || 'https://indexer.pivx.name';

        // 1. Fetch roots and resolved data
        const { rootsMatch, indexerRoot, isNotFound, resolveData } = await getPivxNameRoots(apiEndpoint, strDomain, evmRpc, evmContractAddress);
        
        if (resolvingAlert) resolvingAlert.close();

        if (!rootsMatch) {
            // Verify if the indexer's root exists historically on the contract
            const isRootValid = await verifyRootValidityOnContract(evmRpc, evmContractAddress, indexerRoot);
            if (!isRootValid) {
                pendingSendParams.value = null; // Clear to prevent any send
                showSyncModal.value = true;
                syncModalState.value = 'invalid_root';
                syncModalTitle.value = '⚠️ Security Warning';
                syncModalText.value = "The Name Service indexer returned a state root that has never been registered on the blockchain. Sending funds is blocked for security reasons.";
                syncModalCancelText.value = 'Close';
                return;
            }

            // Roots mismatch! Keep send params for resumption
            pendingSendParams.value = {
                address: isNotFound ? '' : resolveData.target_address,
                amount,
                useShieldInputs,
                memo,
                originalDomain: strDomain,
                resolveData: isNotFound ? null : resolveData
            };
            
            if (!isNotFound && resolveData && resolveData.target_address) {
                // State A: Domain Resolved (Roots Mismatch)
                showSyncModal.value = true;
                syncModalState.value = 'warning';
                syncModalTitle.value = '⚠️ Indexer Sync Delay';
                syncModalText.value = "The Name Service is currently syncing with the latest state from PIVX blockchain. If the owner changed this domain's target address in the last 10-20 minutes, funds might go to the old address.";
                syncModalConfirmText.value = 'Send anyway';
                syncModalCancelText.value = 'Cancel';
                
                startSyncModalPolling(apiEndpoint, strDomain, evmRpc, evmContractAddress);
            } else {
                // State B: Domain Not Found (Roots Mismatch)
                showSyncModal.value = true;
                syncModalState.value = 'not_found';
                syncModalTitle.value = '🔍 Indexer Sync Delay';
                syncModalText.value = "The Name Service is currently syncing with the latest state from PIVX blockchain, and this domain name was not found. If it was registered very recently, it might be syncing at the moment.";
                syncModalCancelText.value = 'Cancel';
                
                startSyncModalPolling(apiEndpoint, strDomain, evmRpc, evmContractAddress);
            }
            return;
        }

        // Roots matched! Check if resolved target was found
        if (isNotFound || !resolveData || !resolveData.target_address) {
            return createAlert('warning', `Domain name ${strDomain} could not be resolved.`, 5000);
        }

        // Run cryptographic verification before sending!
        if (verifyResolvedDetails(strDomain, resolveData)) {
            emit('send', { 
                address: resolveData.target_address, 
                amount, 
                useShieldInputs, 
                memo 
            });
        }

    } catch (e) {
        if (resolvingAlert) resolvingAlert.close();
        console.error("Name service resolution error:", e);
        createAlert('warning', `Failed to resolve domain name: ${e.message || e}`, 5000);
    }
}

// Expose public API
defineExpose({
    resolveAndVerify
});
</script>

<template>
    <!-- Sync Warning Modal -->
    <div
        v-if="showSyncModal"
        class="modal fade show"
        style="display: block; background: rgba(0, 0, 0, 0.6); z-index: 1050; overflow-y: auto;"
        tabindex="-1"
        role="dialog"
    >
        <div class="modal-dialog modal-dialog-centered" role="document">
            <div class="modal-content text-center" style="background: #1e1233; color: #fff; border: 1px solid #4e327a; border-radius: 10px; padding: 20px;">
                <div class="modal-header border-0 justify-content-center" style="padding-bottom: 0;">
                    <h5 class="modal-title font-weight-bold" style="color: #d5adff; font-size: 1.35rem;">
                        {{ syncModalTitle }}
                    </h5>
                </div>
                <div class="modal-body border-0" style="font-size: 0.95rem; line-height: 1.5; color: #e1d5f5; padding-top: 15px; padding-bottom: 15px;">
                    <p>{{ syncModalText }}</p>
                    <div v-if="syncModalIsPolling" class="mt-3 d-flex align-items-center justify-content-center" style="color: #d5adff; font-size: 0.85rem; gap: 8px;">
                        <span class="spinner-border spinner-border-sm" role="status" aria-hidden="true" style="width: 1rem; height: 1rem; border-width: 0.15em;"></span>
                        Polling indexer status (roots checking)...
                    </div>
                </div>
                <div class="modal-footer border-0 justify-content-center" style="padding-top: 0; display: flex; gap: 10px;">
                    <button
                        v-if="syncModalState === 'warning' || syncModalState === 'synced'"
                        type="button"
                        class="pivx-button-big"
                        style="width: 150px; margin: 0;"
                        @click="closeSyncModal(true)"
                    >
                        {{ syncModalConfirmText }}
                    </button>
                    <button
                        v-if="syncModalState === 'not_found'"
                        type="button"
                        class="pivx-button-big"
                        style="width: 150px; margin: 0;"
                        @click="retrySyncModalResolution"
                    >
                        Retry
                    </button>
                    <button
                        type="button"
                        class="pivx-button-big-cancel"
                        style="width: 150px; margin: 0;"
                        @click="closeSyncModal(false)"
                    >
                        {{ syncModalCancelText }}
                    </button>
                </div>
            </div>
        </div>
    </div>
</template>
