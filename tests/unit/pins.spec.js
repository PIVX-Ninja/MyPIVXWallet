import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { verifySmtProof, fetchArbitrumRoot, fetchIndexerRoot, verifyRootValidityOnContract, isPIVXName, isPIVXNameTLD, PIVXNameTLDs } from '../../scripts/utils.pins.js';
import { mount } from '@vue/test-utils';
import PiNS from '../../scripts/dashboard/PiNS.vue';
import { Database } from '../../scripts/database.js';

vi.mock('../../scripts/i18n.js', () => {
    const translation = {
        pinsPolling: 'Polling...',
        pinsTitleSecurityWarning: 'Security Warning',
        pinsTextSecurityWarning: 'The Name Service indexer returned a state root that has never been registered on the blockchain.',
        pinsTitleSynced: 'Synced',
        pinsTextSynced: 'Synced success.',
        pinsTitleNotFound: 'Not Found',
        pinsTextNotFound: 'Not found.',
        pinsTitleSyncDelay: 'Sync Delay',
        pinsTextSyncDelayResolved: 'Sync delay.',
        pinsTitleSyncDelayNotFound: 'Sync Delay Not Found',
        pinsTextSyncDelayNotFound: 'Sync delay not found.',
        pinsTitleIndexerError: 'Indexer Error',
        pinsTextIndexerError: 'Error: {errMsg}',
        pinsBtnClose: 'Close',
        pinsBtnSend: 'Send',
        pinsBtnSendAnyway: 'Send anyway',
        pinsBtnCancel: 'Cancel',
        pinsBtnRetry: 'Retry'
    };
    const ALERTS = {
        PINS_RESOLVING_DOMAIN: 'Resolving {strDomain}...',
        PINS_CHECKING_SYNC: 'Checking sync...',
        PINS_SYNCING_WAIT: 'Syncing...',
        PINS_SYNC_FAILED: 'Sync failed: {errMsg}',
        PINS_RESOLVE_FAILED: 'Resolve failed: {errMsg}',
        PINS_INVALID_FORMAT: 'Invalid format',
        PINS_INCOMPLETE_METADATA: 'Incomplete metadata',
        PINS_INVALID_PROOF: 'Invalid proof',
        PINS_INVALID_SHIELD: 'Invalid shield',
        PINS_NAME_MISMATCH: 'Name mismatch',
        PINS_NOT_FOUND: 'Not found'
    };
    return {
        translation,
        ALERTS,
        tr: (message, variables) => {
            if (!message) return '';
            variables.forEach((element) => {
                message = message.replaceAll(
                    '{' + Object.keys(element)[0] + '}',
                    Object.values(element)[0]
                );
            });
            return message;
        },
        switchTranslation: vi.fn()
    };
});

describe('verifySmtProof', () => {
    it('should cryptographically verify the Sparse Merkle Tree (SMT) proof of a resolved name', () => {
        const domainName = 'alex.pivx';
        const targetAddress = 'pts10nwz757gl22x80lupd3vfa3t5s4jhqfq0krgtv0m7gcr5t42eq8ugdww3tpluqjyqlp55z6x39r';
        const ownerPubkey = '3757ee1a8b3f10353ca6edd47b66920392b02e323dca3f3edddb5de142079a53';
        const price = 0;
        const nonce = 1782739295;
        const expectedRoot = '7fbe8f29f7278db7a665de4f1255927b40b648b43e55b34bb3e0405edb5e7d12';
        
        const merkleProof = [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
            "db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71",
            "c78009fdf07fc56a11f122370658a353aaa542ed63e44c4bc15ff4cd105ab33c",
            "536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c",
            "9efde052aa15429fae05bad4d0b1d7c64da64d03d7a1854a588c2cb8430c0d30",
            "d88ddfeed400a8755596b21942c1497e114c302e6118290f91e6772976041fa1",
            "87eb0ddba57e35f6d286673802a4af5975e22506c7cf4c64bb6be5ee11527f2c",
            "26846476fd5fc54a5d43385167c95144f2643f533cc85bb9d16b782f8d7db193",
            "506d86582d252405b840018792cad2bf1259f1ef5aa5f887e13cb2f0094f51e1",
            "ffff0ad7e659772f9534c195c815efc4014ef1e1daed4404c06385d11192e92b",
            "6cf04127db05441cd833107a52be852868890e4317e6a02ab47683aa75964220",
            "b7d05f875f140027ef5118a2247bbb84ce8f2f0f1123623085daf7960c329f5f",
            "df6af5f5bbdb6be9ef8aa618e4bf8073960867171e29676f8b284dea6a08a85e",
            "b58d900f5e182e3c50ef74969ea16c7726c549757cc23523c369587da7293784",
            "d49a7502ffcfb0340b1d7885688500ca308161a7f96b62df9d083b71fcc8f2bb",
            "8fe6b1689256c0d385f42f5bbe2027a22c1996e110ba97c171d3e5948de92beb",
            "8d0d63c39ebade8509e0ae3c9c3876fb5fa112be18f905ecacfecb92057603ab",
            "95eec8b2e541cad4e91de38385f2e046619f54496c2382cb6cacd5b98c26f5a4",
            "f893e908917775b62bff23294dbbe3a1cd8e6cc1c35b4801887b646a6f81f17f",
            "cddba7b592e3133393c16194fac7431abf2f5485ed711db282183c819e08ebaa",
            "8a8d7fe3af8caa085a7639a832001457dfb9128a8061142ad0335629ff23ff9c",
            "feb3c337d7a51a6fbf00b9e34c52e1c9195c969bd4e7a0bfd51d5c5bed9c1167",
            "e71f0aa83cc32edfbefa9f4d3e0174ca85182eec9f3a09f6a6c0df6377a510d7",
            "31206fa80a50bb6abe29085058f16212212a60eec8f049fecb92d8c8e0a84bc0",
            "21352bfecbeddde993839f614c3dac0a3ee37543f9b412b16199dc158e23b544",
            "619e312724bb6d7c3153ed9de791d764a366b389af13c58bf8a8d90481a46765",
            "7cdd2986268250628d0c10e385c58c6191e6fbe05191bcc04f133f2cea72c1c4",
            "848930bd7ba8cac54661072113fb278869e07bb8587f91392933374d017bcbe1",
            "8869ff2c22b28cc10510d9853292803328be4fb0e80495e8bb8d271f5b889636",
            "b5fe28e79f1b850f8658246ce9b6a1e7b49fc06db7143e8fe0b4f2b0c5523a5c",
            "985e929f70af28d0bdd1a90a808f977f597c7c778c489e98d3bd8910d31ac0f7",
            "c6f67e02e6e4e1bdefb994c6098953f34636ba2b6ca20a4721d2b26a886722ff",
            "1c9a7e5ff1cf48b4ad1582d3f4e4a1004f3b20d8c5a2b71387a4254ad933ebc5",
            "2f075ae229646b6f6aed19a5e372cf295081401eb893ff599b3f9acc0c0d3e7d",
            "328921deb59612076801e8cd61592107b5c67c79b846595cc6320c395b46362c",
            "bfb909fdb236ad2411b4e4883810a074b840464689986c3f8a8091827e17c327",
            "55d8fb3687ba3ba49f342c77f5a1f89bec83d811446e1a467139213d640b6a74",
            "f7210d4f8e7e1039790e7bf4efa207555a10a6db1dd4b95da313aaa88b88fe76",
            "ad21b516cbc645ffe34ab5de1c8aef8cd4e7f8d2b51e8e1456adc7563cda206f",
            "6bfe8d2bcc4237b74a5047058ef455339ecd7360cb63bfbb8ee5448e6430ba04",
            "a7f23ce9181740dc220c814782654fee6aceb9f1ec9222c4e2467d0ab1680837",
            "aef9476c89590a2c8cc9b3b74f4967c757c49d9866a44bacf21fa2ed675ddfa2",
            "9a42bcad82f6a9e41284d808ead319f29f3b08209d680f0e2ce71510d071e205",
            "d1a66d354a67b9cf179571d8e5f97792716e8dd4ec44196839a3f7c6b74f8bac",
            "fafa3025f2f89509c2c71c74fba0cd92858ef49b0780fb5479746c8a9bfcb346",
            "3334a7c1e7f6705aa6011a6a949645016db4acde0ca9abd66dc79d8266423056",
            "0796fd75664faef744ee4e52d7271e2bbb769f91ed6f9b74d8b694f56606852c",
            "7ba3ae4a417fe8545b142bc89f4adcd7ae13941cbab7750b83e9f0a66d16be64",
            "788fafcc4aa520399adbaed195f8b12c4eb31ec10168e50aabc659a6aea516dc",
            "e833d7a67160e68bf4c9044a53077df2727ad00cf36f4949c7b681a912140cbb",
            "309eabf095dc6714f9f4d864bba5affae0b35ae2f5e3565bcc3a47b212767701",
            "226a8ebefa288665a644a50273335efbb610510f241b5b720c8a368d59a69a5d",
            "41abfd995425827625938131af0c4f33fe0bd4688c222c21fa9da8e89caa03f8",
            "442c642ef50fa1a667a6e6d105c77c5cc3fec8d7aa2570cf1a3077b503c38069",
            "a0a08dfc9b42d96c2de19b6d127b8ae136ddcf3e5ad0dce422c45a56f61f6a74",
            "7d348382af096dbe0bf086c7bb39b2a2c0bc36b621ab0c738e9885d731d81740",
            "3ab134751d191269026c86994eaa8b43a83b4ad1f6d0e77381c4e2974afbc8f6",
            "9a7452611db2d23eae26f9bdbb88958ef44c64d0fe987be9f726adf938f50f6c",
            "725c7f816037bfe452cd1e7ba35ac47edcb49a9a2b27aeca70dce483cb7ded1f",
            "2cea1af51fb28b62887c39998ac9fef4dfdeda1f07e071ba558a173afd06cbc3",
            "ff1d59f98b6c551d95089357057d5c8be26402279e9df0b1df1a10b72bf3927f",
            "2f8a181f7c99dd215a7529bfe296a9603a1446737186d21aeb8bc7ae59e1fd21",
            "ecc502c9b1145f3950cb7d3e3842446f81a4f0df1df537cee139ef64ea984bd9",
            "c885c236140249c9e1640e5e99fb972d81fbb31ea5e29fbdde063627f0d6bdc8",
            "303ce38809ba7a77b660ad0b074af9c6bcd5c02bbff2f3b0248633b0b876e449",
            "2fd4c32b0a65616d4bceb9e2f2bd4dcf7535546f433a3e1d45ce54abc059c867",
            "2f8d300488ab4f7464d9ee9e59d80aaa8a2039af5513f320e5a3083c63ea68ef",
            "48562f2ab1873a6120f575267a37db470d4a6bc83ed1ad903e64f7b3755766ad",
            "2820f9073707ceff6a0e5e2bcfca8d73d235ade70d0afd535c9177fb9266c9f7",
            "f3f6a8151f64f6bdddc4b8c0963c5712eef47d6eb432f12699c5295914f08ea2",
            "2ea941b101d99e7b6b18a6a62a0f573c4b80d0c68ca1d15f885de9ce0b4fc488",
            "8212c49b0949693091c6672a06241f3df865a676cccdcbd16f0615eea6068383",
            "e726e40dbd2f9841293b5b3c15e918a872aed2ba491f4e111ea0913a04ffe165",
            "7729475e1ace968d096a7cbf0b88348158a37eef64b90994cbd37ddc3adf5370",
            "fc487e466c2bf48d87b5d66f5aa24f9c5b3f990e210f5065050d5208d59b6b87",
            "77fc88582c114fb77e9bc6666e3f3fc6e89e4cbd3dd1590a6f67adb547f348d5",
            "dc243614ffda79e3d7556ef3fdea0b44df1757badae017b05f5133fd15c27aea",
            "e705095fe3ed6cb2da458664229c5158d88aa0f775528dfb27ff3ffe270fc0c9",
            "779f1ecbfae3d0e1e7328817446dbf4bcb6a678c6ca4e2726e9f3e6e65fcdaca",
            "5e5c577e401fb0ed3c051979201cfc5ec100dae9942278e99e3434cfe560c276",
            "1894ce6124659cb0d6f90a84424e372b59dd7e7220bdb16804539b51ba7c6ef1",
            "641edf1965e87a70428712727ed1db13b2de91ed574c83b28339bc7502aec3f2",
            "0a36dc4d1b170aec654cd6e3886f6ae3a2448d30a95e3ae5c56b7a5b00cb8f3d",
            "571968a6a58857784b13e1bf9480285a7ae70ddf2e321d06b17cf0a933119cdd",
            "e56813628ec57e8de059bca787d1ef7cb1cb9f608c6ba0bf780277beddbd3f27",
            "5ef1e53a05f43d01472447d914409459ce5f2b0d24566187efdbefc25864da2b",
            "ad19b79824b2a80a8b891450d2c7fccf9e51c25979b37dba8ed597fb93ba9d9d",
            "180fedca06656cb910077013ad2679695090269fad1589e290162fe90e97d4aa",
            "73f472650e8da09bcf2c8cb998db52bb27bba5c6335d4844323d68094c1028f8",
            "ff746696955cfa91aed5e76102710dfe2e278279bf543de9c3df8a7134a33b64",
            "2e98ae4b6e69b95b71048ec119719851c050529a20c67a2c401723b34de9748a",
            "3b5c39d7274c2a74d4ed2d9e8410ead2f351dfd6158148f1b10d97d60d739207",
            "423f672311c1a44ce5a44765f6217eabf759de2bd882b6bf0f7b09694e4b8043",
            "a3ba0d85049395335718883c7451cd3d10a326b1d73e223aa5549ee68c3beabf",
            "d3d47dffaa99a033c8c3bb62dc0a438b71f91b18a38c87a49fa88474dde87924",
            "4189d201eed3f4ebcb3fd5a4c73f282923f010e753c3c5e7e3d0199037a3b087",
            "142a03b09d66cbe5b45fea8fa25d6a297084aed9e03bee72862f9d6b3dbabba0",
            "4cd8ea52aca52408fb87b0e697cd24632d94a6df757fa3f29cc0a5d5494edcc5",
            "afa2c75dc2c5a8462c17092ee1efe21de9b10f0dc0dea0794f304513e1aa33d2",
            "3d39740655edfc46fb8afd539e23070dfb35e0d6d1cf67eed7a1c25442e01696",
            "7d609e3eee6fa33910f427d52e88efcca673e453b4acde37a8a8687f3d3af57a",
            "7811af413c13feec4a8c2774f189a7e24069b688700756b947de0157185432c6",
            "571c032857aadbec07310299b0041c26924a619669e161559a5b1f49aff9cc09",
            "0a6b5e75c36a716b43d41d262adb047d165da4c39a512f145f5fc90f86923ea3",
            "547374ec1a58c7a4d14d51afb52ed4e404a9eb22f008b3387d326edbd3066c77",
            "f9e4305daad80dfb3776230d54edddf5050cefe0846999414c706ea60aa3fe11",
            "560094093e5d3692d4918b79804f7eb6a0a1868000aac0659090d995c2377045",
            "95cba54239a7304d36b0530219dfb8446e85ddc9bb6d401f6324fd888bdae4f7",
            "ef97d5ba70031de19734533a11bc7a52ca5b05c3b1d2c61d53010a57878dae8d",
            "854accef35670517593e126a933f9a77ffb7b6ced2735f5518f5dc16b16ec0cd",
            "7f11203031a72517235fc9bcf05675a6f67062c3e2db8ec26f6841bc04125818",
            "313a6522e9eaae01ff1e4bb545c042d2ce3a7271f668ecaa303b54eb70ebf294",
            "bcfd4c9b524c615b741dd6f5d4aea9779e53eae70e56b884d238c96859f4b745",
            "38e5e5559730caf93710ca7937ceb17511e70d5356979a700223828f5b58e9e9",
            "c39ed9a49132e90199629a542f75e932dfc2a808684e19719af55eaa5b7da7fc",
            "6b28b005159e4c86a041c4d927db665863bf9d1b24b1660d802f50dbdd84ab07",
            "53eb316498b48aa6edc5b6a5ae8299430d2696a588c576febef380d965bc6e8c",
            "77a3fe503f5c11aaf32d40ac768143769cd0f21ff89214ffda1bdbc69a5d4ace",
            "d32df6cd44214942706b01b785b310d0102e1acb64b9786f1c5d666f3c4d796b",
            "27803233e079f2509c07cbb25962a808c7a6c65f8a99bd99fe54da707b9a45a4",
            "765ff12c95a406baf48020d6ae348e2021a94ce6b40c1426ea4c44a74cab228c",
            "d0522d45ad5883d1dfe4c36925a94fcbc30e828083a87c53ccaa12cd679fed56",
            "a52cb2ecc93349c4a6bd2f7978c4c9038ebc508211a2eb6a066e33b2bc9a529a",
            "ec62a0632977f6fd261698a38df08b62cc56996838b0b19de2a398e7a0429066",
            "088bc060f99c193b0168c7247e1a0622585bcbf802672e011c3bfb4d88b2cf81",
            "811f21aad5eaa9a405c38f7a0237d0e5d7d8e8fe7ace45d14bb6033ca8649c89",
            "c284d0ee4ad15a89034e76f5b3766998ac77ac50c45628680051767063646169"
        ];

        const smtRoot = expectedRoot;

        expect(verifySmtProof(domainName, targetAddress, ownerPubkey, price, nonce, merkleProof, smtRoot)).toBe(true);
    });

    it('should return false if the domain name or target address does not match the proof', () => {
        const domainName = 'alex.pivx';
        const targetAddress = 'pts10nwz757gl22x80lupd3vfa3t5s4jhqfq0krgtv0m7gcr5t42eq8ugdww3tpluqjyqlp55z6x39r';
        const ownerPubkey = '3757ee1a8b3f10353ca6edd47b66920392b02e323dca3f3edddb5de142079a53';
        const price = 0;
        const nonce = 1782739295;
        const expectedRoot = '7fbe8f29f7278db7a665de4f1255927b40b648b43e55b34bb3e0405edb5e7d12';
        
        const merkleProof = [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
            "db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71",
            "c78009fdf07fc56a11f122370658a353aaa542ed63e44c4bc15ff4cd105ab33c",
            "536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c",
            "9efde052aa15429fae05bad4d0b1d7c64da64d03d7a1854a588c2cb8430c0d30",
            "d88ddfeed400a8755596b21942c1497e114c302e6118290f91e6772976041fa1",
            "87eb0ddba57e35f6d286673802a4af5975e22506c7cf4c64bb6be5ee11527f2c",
            "26846476fd5fc54a5d43385167c95144f2643f533cc85bb9d16b782f8d7db193",
            "506d86582d252405b840018792cad2bf1259f1ef5aa5f887e13cb2f0094f51e1",
            "ffff0ad7e659772f9534c195c815efc4014ef1e1daed4404c06385d11192e92b",
            "6cf04127db05441cd833107a52be852868890e4317e6a02ab47683aa75964220",
            "b7d05f875f140027ef5118a2247bbb84ce8f2f0f1123623085daf7960c329f5f",
            "df6af5f5bbdb6be9ef8aa618e4bf8073960867171e29676f8b284dea6a08a85e",
            "b58d900f5e182e3c50ef74969ea16c7726c549757cc23523c369587da7293784",
            "d49a7502ffcfb0340b1d7885688500ca308161a7f96b62df9d083b71fcc8f2bb",
            "8fe6b1689256c0d385f42f5bbe2027a22c1996e110ba97c171d3e5948de92beb",
            "8d0d63c39ebade8509e0ae3c9c3876fb5fa112be18f905ecacfecb92057603ab",
            "95eec8b2e541cad4e91de38385f2e046619f54496c2382cb6cacd5b98c26f5a4",
            "f893e908917775b62bff23294dbbe3a1cd8e6cc1c35b4801887b646a6f81f17f",
            "cddba7b592e3133393c16194fac7431abf2f5485ed711db282183c819e08ebaa",
            "8a8d7fe3af8caa085a7639a832001457dfb9128a8061142ad0335629ff23ff9c",
            "feb3c337d7a51a6fbf00b9e34c52e1c9195c969bd4e7a0bfd51d5c5bed9c1167",
            "e71f0aa83cc32edfbefa9f4d3e0174ca85182eec9f3a09f6a6c0df6377a510d7",
            "31206fa80a50bb6abe29085058f16212212a60eec8f049fecb92d8c8e0a84bc0",
            "21352bfecbeddde993839f614c3dac0a3ee37543f9b412b16199dc158e23b544",
            "619e312724bb6d7c3153ed9de791d764a366b389af13c58bf8a8d90481a46765",
            "7cdd2986268250628d0c10e385c58c6191e6fbe05191bcc04f133f2cea72c1c4",
            "848930bd7ba8cac54661072113fb278869e07bb8587f91392933374d017bcbe1",
            "8869ff2c22b28cc10510d9853292803328be4fb0e80495e8bb8d271f5b889636",
            "b5fe28e79f1b850f8658246ce9b6a1e7b49fc06db7143e8fe0b4f2b0c5523a5c",
            "985e929f70af28d0bdd1a90a808f977f597c7c778c489e98d3bd8910d31ac0f7",
            "c6f67e02e6e4e1bdefb994c6098953f34636ba2b6ca20a4721d2b26a886722ff",
            "1c9a7e5ff1cf48b4ad1582d3f4e4a1004f3b20d8c5a2b71387a4254ad933ebc5",
            "2f075ae229646b6f6aed19a5e372cf295081401eb893ff599b3f9acc0c0d3e7d",
            "328921deb59612076801e8cd61592107b5c67c79b846595cc6320c395b46362c",
            "bfb909fdb236ad2411b4e4883810a074b840464689986c3f8a8091827e17c327",
            "55d8fb3687ba3ba49f342c77f5a1f89bec83d811446e1a467139213d640b6a74",
            "f7210d4f8e7e1039790e7bf4efa207555a10a6db1dd4b95da313aaa88b88fe76",
            "ad21b516cbc645ffe34ab5de1c8aef8cd4e7f8d2b51e8e1456adc7563cda206f",
            "6bfe8d2bcc4237b74a5047058ef455339ecd7360cb63bfbb8ee5448e6430ba04",
            "a7f23ce9181740dc220c814782654fee6aceb9f1ec9222c4e2467d0ab1680837",
            "aef9476c89590a2c8cc9b3b74f4967c757c49d9866a44bacf21fa2ed675ddfa2",
            "9a42bcad82f6a9e41284d808ead319f29f3b08209d680f0e2ce71510d071e205",
            "d1a66d354a67b9cf179571d8e5f97792716e8dd4ec44196839a3f7c6b74f8bac",
            "fafa3025f2f89509c2c71c74fba0cd92858ef49b0780fb5479746c8a9bfcb346",
            "3334a7c1e7f6705aa6011a6a949645016db4acde0ca9abd66dc79d8266423056",
            "0796fd75664faef744ee4e52d7271e2bbb769f91ed6f9b74d8b694f56606852c",
            "7ba3ae4a417fe8545b142bc89f4adcd7ae13941cbab7750b83e9f0a66d16be64",
            "788fafcc4aa520399adbaed195f8b12c4eb31ec10168e50aabc659a6aea516dc",
            "e833d7a67160e68bf4c9044a53077df2727ad00cf36f4949c7b681a912140cbb",
            "309eabf095dc6714f9f4d864bba5affae0b35ae2f5e3565bcc3a47b212767701",
            "226a8ebefa288665a644a50273335efbb610510f241b5b720c8a368d59a69a5d",
            "41abfd995425827625938131af0c4f33fe0bd4688c222c21fa9da8e89caa03f8",
            "442c642ef50fa1a667a6e6d105c77c5cc3fec8d7aa2570cf1a3077b503c38069",
            "a0a08dfc9b42d96c2de19b6d127b8ae136ddcf3e5ad0dce422c45a56f61f6a74",
            "7d348382af096dbe0bf086c7bb39b2a2c0bc36b621ab0c738e9885d731d81740",
            "3ab134751d191269026c86994eaa8b43a83b4ad1f6d0e77381c4e2974afbc8f6",
            "9a7452611db2d23eae26f9bdbb88958ef44c64d0fe987be9f726adf938f50f6c",
            "725c7f816037bfe452cd1e7ba35ac47edcb49a9a2b27aeca70dce483cb7ded1f",
            "2cea1af51fb28b62887c39998ac9fef4dfdeda1f07e071ba558a173afd06cbc3",
            "ff1d59f98b6c551d95089357057d5c8be26402279e9df0b1df1a10b72bf3927f",
            "2f8a181f7c99dd215a7529bfe296a9603a1446737186d21aeb8bc7ae59e1fd21",
            "ecc502c9b1145f3950cb7d3e3842446f81a4f0df1df537cee139ef64ea984bd9",
            "c885c236140249c9e1640e5e99fb972d81fbb31ea5e29fbdde063627f0d6bdc8",
            "303ce38809ba7a77b660ad0b074af9c6bcd5c02bbff2f3b0248633b0b876e449",
            "2fd4c32b0a65616d4bceb9e2f2bd4dcf7535546f433a3e1d45ce54abc059c867",
            "2f8d300488ab4f7464d9ee9e59d80aaa8a2039af5513f320e5a3083c63ea68ef",
            "48562f2ab1873a6120f575267a37db470d4a6bc83ed1ad903e64f7b3755766ad",
            "2820f9073707ceff6a0e5e2bcfca8d73d235ade70d0afd535c9177fb9266c9f7",
            "f3f6a8151f64f6bdddc4b8c0963c5712eef47d6eb432f12699c5295914f08ea2",
            "2ea941b101d99e7b6b18a6a62a0f573c4b80d0c68ca1d15f885de9ce0b4fc488",
            "8212c49b0949693091c6672a06241f3df865a676cccdcbd16f0615eea6068383",
            "e726e40dbd2f9841293b5b3c15e918a872aed2ba491f4e111ea0913a04ffe165",
            "7729475e1ace968d096a7cbf0b88348158a37eef64b90994cbd37ddc3adf5370",
            "fc487e466c2bf48d87b5d66f5aa24f9c5b3f990e210f5065050d5208d59b6b87",
            "77fc88582c114fb77e9bc6666e3f3fc6e89e4cbd3dd1590a6f67adb547f348d5",
            "dc243614ffda79e3d7556ef3fdea0b44df1757badae017b05f5133fd15c27aea",
            "e705095fe3ed6cb2da458664229c5158d88aa0f775528dfb27ff3ffe270fc0c9",
            "779f1ecbfae3d0e1e7328817446dbf4bcb6a678c6ca4e2726e9f3e6e65fcdaca",
            "5e5c577e401fb0ed3c051979201cfc5ec100dae9942278e99e3434cfe560c276",
            "1894ce6124659cb0d6f90a84424e372b59dd7e7220bdb16804539b51ba7c6ef1",
            "641edf1965e87a70428712727ed1db13b2de91ed574c83b28339bc7502aec3f2",
            "0a36dc4d1b170aec654cd6e3886f6ae3a2448d30a95e3ae5c56b7a5b00cb8f3d",
            "571968a6a58857784b13e1bf9480285a7ae70ddf2e321d06b17cf0a933119cdd",
            "e56813628ec57e8de059bca787d1ef7cb1cb9f608c6ba0bf780277beddbd3f27",
            "5ef1e53a05f43d01472447d914409459ce5f2b0d24566187efdbefc25864da2b",
            "ad19b79824b2a80a8b891450d2c7fccf9e51c25979b37dba8ed597fb93ba9d9d",
            "180fedca06656cb910077013ad2679695090269fad1589e290162fe90e97d4aa",
            "73f472650e8da09bcf2c8cb998db52bb27bba5c6335d4844323d68094c1028f8",
            "ff746696955cfa91aed5e76102710dfe2e278279bf543de9c3df8a7134a33b64",
            "2e98ae4b6e69b95b71048ec119719851c050529a20c67a2c401723b34de9748a",
            "3b5c39d7274c2a74d4ed2d9e8410ead2f351dfd6158148f1b10d97d60d739207",
            "423f672311c1a44ce5a44765f6217eabf759de2bd882b6bf0f7b09694e4b8043",
            "a3ba0d85049395335718883c7451cd3d10a326b1d73e223aa5549ee68c3beabf",
            "d3d47dffaa99a033c8c3bb62dc0a438b71f91b18a38c87a49fa88474dde87924",
            "4189d201eed3f4ebcb3fd5a4c73f282923f010e753c3c5e7e3d0199037a3b087",
            "142a03b09d66cbe5b45fea8fa25d6a297084aed9e03bee72862f9d6b3dbabba0",
            "4cd8ea52aca52408fb87b0e697cd24632d94a6df757fa3f29cc0a5d5494edcc5",
            "afa2c75dc2c5a8462c17092ee1efe21de9b10f0dc0dea0794f304513e1aa33d2",
            "3d39740655edfc46fb8afd539e23070dfb35e0d6d1cf67eed7a1c25442e01696",
            "7d609e3eee6fa33910f427d52e88efcca673e453b4acde37a8a8687f3d3af57a",
            "7811af413c13feec4a8c2774f189a7e24069b688700756b947de0157185432c6",
            "571c032857aadbec07310299b0041c26924a619669e161559a5b1f49aff9cc09",
            "0a6b5e75c36a716b43d41d262adb047d165da4c39a512f145f5fc90f86923ea3",
            "547374ec1a58c7a4d14d51afb52ed4e404a9eb22f008b3387d326edbd3066c77",
            "f9e4305daad80dfb3776230d54edddf5050cefe0846999414c706ea60aa3fe11",
            "560094093e5d3692d4918b79804f7eb6a0a1868000aac0659090d995c2377045",
            "95cba54239a7304d36b0530219dfb8446e85ddc9bb6d401f6324fd888bdae4f7",
            "ef97d5ba70031de19734533a11bc7a52ca5b05c3b1d2c61d53010a57878dae8d",
            "854accef35670517593e126a933f9a77ffb7b6ced2735f5518f5dc16b16ec0cd",
            "7f11203031a72517235fc9bcf05675a6f67062c3e2db8ec26f6841bc04125818",
            "313a6522e9eaae01ff1e4bb545c042d2ce3a7271f668ecaa303b54eb70ebf294",
            "bcfd4c9b524c615b741dd6f5d4aea9779e53eae70e56b884d238c96859f4b745",
            "38e5e5559730caf93710ca7937ceb17511e70d5356979a700223828f5b58e9e9",
            "c39ed9a49132e90199629a542f75e932dfc2a808684e19719af55eaa5b7da7fc",
            "6b28b005159e4c86a041c4d927db665863bf9d1b24b1660d802f50dbdd84ab07",
            "53eb316498b48aa6edc5b6a5ae8299430d2696a588c576febef380d965bc6e8c",
            "77a3fe503f5c11aaf32d40ac768143769cd0f21ff89214ffda1bdbc69a5d4ace",
            "d32df6cd44214942706b01b785b310d0102e1acb64b9786f1c5d666f3c4d796b",
            "27803233e079f2509c07cbb25962a808c7a6c65f8a99bd99fe54da707b9a45a4",
            "765ff12c95a406baf48020d6ae348e2021a94ce6b40c1426ea4c44a74cab228c",
            "d0522d45ad5883d1dfe4c36925a94fcbc30e828083a87c53ccaa12cd679fed56",
            "a52cb2ecc93349c4a6bd2f7978c4c9038ebc508211a2eb6a066e33b2bc9a529a",
            "ec62a0632977f6fd261698a38df08b62cc56996838b0b19de2a398e7a0429066",
            "088bc060f99c193b0168c7247e1a0622585bcbf802672e011c3bfb4d88b2cf81",
            "811f21aad5eaa9a405c38f7a0237d0e5d7d8e8fe7ace45d14bb6033ca8649c89",
            "c284d0ee4ad15a89034e76f5b3766998ac77ac50c45628680051767063646169"
        ];

        const smtRoot = expectedRoot;

        expect(verifySmtProof(domainName, targetAddress, ownerPubkey, price, nonce, merkleProof, smtRoot)).toBe(true);
    });

    it('should return false if the domain name or target address does not match the proof', () => {
        const domainName = 'alex.pivx';
        const targetAddress = 'pts10nwz757gl22x80lupd3vfa3t5s4jhqfq0krgtv0m7gcr5t42eq8ugdww3tpluqjyqlp55z6x39r';
        const ownerPubkey = '3757ee1a8b3f10353ca6edd47b66920392b02e323dca3f3edddb5de142079a53';
        const price = 0;
        const nonce = 1782739295;
        const expectedRoot = '7fbe8f29f7278db7a665de4f1255927b40b648b43e55b34bb3e0405edb5e7d12';
        
        const merkleProof = [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
            "db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71",
            "c78009fdf07fc56a11f122370658a353aaa542ed63e44c4bc15ff4cd105ab33c",
            "536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c",
            "9efde052aa15429fae05bad4d0b1d7c64da64d03d7a1854a588c2cb8430c0d30",
            "d88ddfeed400a8755596b21942c1497e114c302e6118290f91e6772976041fa1",
            "87eb0ddba57e35f6d286673802a4af5975e22506c7cf4c64bb6be5ee11527f2c",
            "26846476fd5fc54a5d43385167c95144f2643f533cc85bb9d16b782f8d7db193",
            "506d86582d252405b840018792cad2bf1259f1ef5aa5f887e13cb2f0094f51e1",
            "ffff0ad7e659772f9534c195c815efc4014ef1e1daed4404c06385d11192e92b",
            "6cf04127db05441cd833107a52be852868890e4317e6a02ab47683aa75964220",
            "b7d05f875f140027ef5118a2247bbb84ce8f2f0f1123623085daf7960c329f5f",
            "df6af5f5bbdb6be9ef8aa618e4bf8073960867171e29676f8b284dea6a08a85e",
            "b58d900f5e182e3c50ef74969ea16c7726c549757cc23523c369587da7293784",
            "d49a7502ffcfb0340b1d7885688500ca308161a7f96b62df9d083b71fcc8f2bb",
            "8fe6b1689256c0d385f42f5bbe2027a22c1996e110ba97c171d3e5948de92beb",
            "8d0d63c39ebade8509e0ae3c9c3876fb5fa112be18f905ecacfecb92057603ab",
            "95eec8b2e541cad4e91de38385f2e046619f54496c2382cb6cacd5b98c26f5a4",
            "f893e908917775b62bff23294dbbe3a1cd8e6cc1c35b4801887b646a6f81f17f",
            "cddba7b592e3133393c16194fac7431abf2f5485ed711db282183c819e08ebaa",
            "8a8d7fe3af8caa085a7639a832001457dfb9128a8061142ad0335629ff23ff9c",
            "feb3c337d7a51a6fbf00b9e34c52e1c9195c969bd4e7a0bfd51d5c5bed9c1167",
            "e71f0aa83cc32edfbefa9f4d3e0174ca85182eec9f3a09f6a6c0df6377a510d7",
            "31206fa80a50bb6abe29085058f16212212a60eec8f049fecb92d8c8e0a84bc0",
            "21352bfecbeddde993839f614c3dac0a3ee37543f9b412b16199dc158e23b544",
            "619e312724bb6d7c3153ed9de791d764a366b389af13c58bf8a8d90481a46765",
            "7cdd2986268250628d0c10e385c58c6191e6fbe05191bcc04f133f2cea72c1c4",
            "848930bd7ba8cac54661072113fb278869e07bb8587f91392933374d017bcbe1",
            "8869ff2c22b28cc10510d9853292803328be4fb0e80495e8bb8d271f5b889636",
            "b5fe28e79f1b850f8658246ce9b6a1e7b49fc06db7143e8fe0b4f2b0c5523a5c",
            "985e929f70af28d0bdd1a90a808f977f597c7c778c489e98d3bd8910d31ac0f7",
            "c6f67e02e6e4e1bdefb994c6098953f34636ba2b6ca20a4721d2b26a886722ff",
            "1c9a7e5ff1cf48b4ad1582d3f4e4a1004f3b20d8c5a2b71387a4254ad933ebc5",
            "2f075ae229646b6f6aed19a5e372cf295081401eb893ff599b3f9acc0c0d3e7d",
            "328921deb59612076801e8cd61592107b5c67c79b846595cc6320c395b46362c",
            "bfb909fdb236ad2411b4e4883810a074b840464689986c3f8a8091827e17c327",
            "55d8fb3687ba3ba49f342c77f5a1f89bec83d811446e1a467139213d640b6a74",
            "f7210d4f8e7e1039790e7bf4efa207555a10a6db1dd4b95da313aaa88b88fe76",
            "ad21b516cbc645ffe34ab5de1c8aef8cd4e7f8d2b51e8e1456adc7563cda206f",
            "6bfe8d2bcc4237b74a5047058ef455339ecd7360cb63bfbb8ee5448e6430ba04",
            "a7f23ce9181740dc220c814782654fee6aceb9f1ec9222c4e2467d0ab1680837",
            "aef9476c89590a2c8cc9b3b74f4967c757c49d9866a44bacf21fa2ed675ddfa2",
            "9a42bcad82f6a9e41284d808ead319f29f3b08209d680f0e2ce71510d071e205",
            "d1a66d354a67b9cf179571d8e5f97792716e8dd4ec44196839a3f7c6b74f8bac",
            "fafa3025f2f89509c2c71c74fba0cd92858ef49b0780fb5479746c8a9bfcb346",
            "3334a7c1e7f6705aa6011a6a949645016db4acde0ca9abd66dc79d8266423056",
            "0796fd75664faef744ee4e52d7271e2bbb769f91ed6f9b74d8b694f56606852c",
            "7ba3ae4a417fe8545b142bc89f4adcd7ae13941cbab7750b83e9f0a66d16be64",
            "788fafcc4aa520399adbaed195f8b12c4eb31ec10168e50aabc659a6aea516dc",
            "e833d7a67160e68bf4c9044a53077df2727ad00cf36f4949c7b681a912140cbb",
            "309eabf095dc6714f9f4d864bba5affae0b35ae2f5e3565bcc3a47b212767701",
            "226a8ebefa288665a644a50273335efbb610510f241b5b720c8a368d59a69a5d",
            "41abfd995425827625938131af0c4f33fe0bd4688c222c21fa9da8e89caa03f8",
            "442c642ef50fa1a667a6e6d105c77c5cc3fec8d7aa2570cf1a3077b503c38069",
            "a0a08dfc9b42d96c2de19b6d127b8ae136ddcf3e5ad0dce422c45a56f61f6a74",
            "7d348382af096dbe0bf086c7bb39b2a2c0bc36b621ab0c738e9885d731d81740",
            "3ab134751d191269026c86994eaa8b43a83b4ad1f6d0e77381c4e2974afbc8f6",
            "9a7452611db2d23eae26f9bdbb88958ef44c64d0fe987be9f726adf938f50f6c",
            "725c7f816037bfe452cd1e7ba35ac47edcb49a9a2b27aeca70dce483cb7ded1f",
            "2cea1af51fb28b62887c39998ac9fef4dfdeda1f07e071ba558a173afd06cbc3",
            "ff1d59f98b6c551d95089357057d5c8be26402279e9df0b1df1a10b72bf3927f",
            "2f8a181f7c99dd215a7529bfe296a9603a1446737186d21aeb8bc7ae59e1fd21",
            "ecc502c9b1145f3950cb7d3e3842446f81a4f0df1df537cee139ef64ea984bd9",
            "c885c236140249c9e1640e5e99fb972d81fbb31ea5e29fbdde063627f0d6bdc8",
            "303ce38809ba7a77b660ad0b074af9c6bcd5c02bbff2f3b0248633b0b876e449",
            "2fd4c32b0a65616d4bceb9e2f2bd4dcf7535546f433a3e1d45ce54abc059c867",
            "2f8d300488ab4f7464d9ee9e59d80aaa8a2039af5513f320e5a3083c63ea68ef",
            "48562f2ab1873a6120f575267a37db470d4a6bc83ed1ad903e64f7b3755766ad",
            "2820f9073707ceff6a0e5e2bcfca8d73d235ade70d0afd535c9177fb9266c9f7",
            "f3f6a8151f64f6bdddc4b8c0963c5712eef47d6eb432f12699c5295914f08ea2",
            "2ea941b101d99e7b6b18a6a62a0f573c4b80d0c68ca1d15f885de9ce0b4fc488",
            "8212c49b0949693091c6672a06241f3df865a676cccdcbd16f0615eea6068383",
            "e726e40dbd2f9841293b5b3c15e918a872aed2ba491f4e111ea0913a04ffe165",
            "7729475e1ace968d096a7cbf0b88348158a37eef64b90994cbd37ddc3adf5370",
            "fc487e466c2bf48d87b5d66f5aa24f9c5b3f990e210f5065050d5208d59b6b87",
            "77fc88582c114fb77e9bc6666e3f3fc6e89e4cbd3dd1590a6f67adb547f348d5",
            "dc243614ffda79e3d7556ef3fdea0b44df1757badae017b05f5133fd15c27aea",
            "e705095fe3ed6cb2da458664229c5158d88aa0f775528dfb27ff3ffe270fc0c9",
            "779f1ecbfae3d0e1e7328817446dbf4bcb6a678c6ca4e2726e9f3e6e65fcdaca",
            "5e5c577e401fb0ed3c051979201cfc5ec100dae9942278e99e3434cfe560c276",
            "1894ce6124659cb0d6f90a84424e372b59dd7e7220bdb16804539b51ba7c6ef1",
            "641edf1965e87a70428712727ed1db13b2de91ed574c83b28339bc7502aec3f2",
            "0a36dc4d1b170aec654cd6e3886f6ae3a2448d30a95e3ae5c56b7a5b00cb8f3d",
            "571968a6a58857784b13e1bf9480285a7ae70ddf2e321d06b17cf0a933119cdd",
            "e56813628ec57e8de059bca787d1ef7cb1cb9f608c6ba0bf780277beddbd3f27",
            "5ef1e53a05f43d01472447d914409459ce5f2b0d24566187efdbefc25864da2b",
            "ad19b79824b2a80a8b891450d2c7fccf9e51c25979b37dba8ed597fb93ba9d9d",
            "180fedca06656cb910077013ad2679695090269fad1589e290162fe90e97d4aa",
            "73f472650e8da09bcf2c8cb998db52bb27bba5c6335d4844323d68094c1028f8",
            "ff746696955cfa91aed5e76102710dfe2e278279bf543de9c3df8a7134a33b64",
            "2e98ae4b6e69b95b71048ec119719851c050529a20c67a2c401723b34de9748a",
            "3b5c39d7274c2a74d4ed2d9e8410ead2f351dfd6158148f1b10d97d60d739207",
            "423f672311c1a44ce5a44765f6217eabf759de2bd882b6bf0f7b09694e4b8043",
            "a3ba0d85049395335718883c7451cd3d10a326b1d73e223aa5549ee68c3beabf",
            "d3d47dffaa99a033c8c3bb62dc0a438b71f91b18a38c87a49fa88474dde87924",
            "4189d201eed3f4ebcb3fd5a4c73f282923f010e753c3c5e7e3d0199037a3b087",
            "142a03b09d66cbe5b45fea8fa25d6a297084aed9e03bee72862f9d6b3dbabba0",
            "4cd8ea52aca52408fb87b0e697cd24632d94a6df757fa3f29cc0a5d5494edcc5",
            "afa2c75dc2c5a8462c17092ee1efe21de9b10f0dc0dea0794f304513e1aa33d2",
            "3d39740655edfc46fb8afd539e23070dfb35e0d6d1cf67eed7a1c25442e01696",
            "7d609e3eee6fa33910f427d52e88efcca673e453b4acde37a8a8687f3d3af57a",
            "7811af413c13feec4a8c2774f189a7e24069b688700756b947de0157185432c6",
            "571c032857aadbec07310299b0041c26924a619669e161559a5b1f49aff9cc09",
            "0a6b5e75c36a716b43d41d262adb047d165da4c39a512f145f5fc90f86923ea3",
            "547374ec1a58c7a4d14d51afb52ed4e404a9eb22f008b3387d326edbd3066c77",
            "f9e4305daad80dfb3776230d54edddf5050cefe0846999414c706ea60aa3fe11",
            "560094093e5d3692d4918b79804f7eb6a0a1868000aac0659090d995c2377045",
            "95cba54239a7304d36b0530219dfb8446e85ddc9bb6d401f6324fd888bdae4f7",
            "ef97d5ba70031de19734533a11bc7a52ca5b05c3b1d2c61d53010a57878dae8d",
            "854accef35670517593e126a933f9a77ffb7b6ced2735f5518f5dc16b16ec0cd",
            "7f11203031a72517235fc9bcf05675a6f67062c3e2db8ec26f6841bc04125818",
            "313a6522e9eaae01ff1e4bb545c042d2ce3a7271f668ecaa303b54eb70ebf294",
            "bcfd4c9b524c615b741dd6f5d4aea9779e53eae70e56b884d238c96859f4b745",
            "38e5e5559730caf93710ca7937ceb17511e70d5356979a700223828f5b58e9e9",
            "c39ed9a49132e90199629a542f75e932dfc2a808684e19719af55eaa5b7da7fc",
            "6b28b005159e4c86a041c4d927db665863bf9d1b24b1660d802f50dbdd84ab07",
            "53eb316498b48aa6edc5b6a5ae8299430d2696a588c576febef380d965bc6e8c",
            "77a3fe503f5c11aaf32d40ac768143769cd0f21ff89214ffda1bdbc69a5d4ace",
            "d32df6cd44214942706b01b785b310d0102e1acb64b9786f1c5d666f3c4d796b",
            "27803233e079f2509c07cbb25962a808c7a6c65f8a99bd99fe54da707b9a45a4",
            "765ff12c95a406baf48020d6ae348e2021a94ce6b40c1426ea4c44a74cab228c",
            "d0522d45ad5883d1dfe4c36925a94fcbc30e828083a87c53ccaa12cd679fed56",
            "a52cb2ecc93349c4a6bd2f7978c4c9038ebc508211a2eb6a066e33b2bc9a529a",
            "ec62a0632977f6fd261698a38df08b62cc56996838b0b19de2a398e7a0429066",
            "088bc060f99c193b0168c7247e1a0622585bcbf802672e011c3bfb4d88b2cf81",
            "811f21aad5eaa9a405c38f7a0237d0e5d7d8e8fe7ace45d14bb6033ca8649c89",
            "c284d0ee4ad15a89034e76f5b3766998ac77ac50c45628680051767063646169"
        ];

        const smtRoot = expectedRoot;

        const corruptProof = [...merkleProof];
        corruptProof[0] = "1000000000000000000000000000000000000000000000000000000000000000";

        expect(verifySmtProof(domainName, targetAddress, ownerPubkey, price, nonce, corruptProof, smtRoot)).toBe(false);
    });
});

describe('isPIVXName', () => {
    it('should return true for valid domain names with supported TLDs', () => {
        expect(isPIVXName('alex.pivx')).toBe(true);
        expect(isPIVXName('richard.secure')).toBe(true);
        expect(isPIVXName('hello-world.safe')).toBe(true);
        expect(isPIVXName('pivx-123.private')).toBe(true);
        expect(isPIVXName('ALEX.pivx')).toBe(true); // case-insensitive
    });

    it('should return false for invalid formats or unsupported TLDs', () => {
        expect(isPIVXName('alex.pivx2')).toBe(false);
        expect(isPIVXName('alex.pivx.name')).toBe(false);
        expect(isPIVXName('alex')).toBe(false);
        expect(isPIVXName('')).toBe(false);
        expect(isPIVXName(null)).toBe(false);
        expect(isPIVXName(undefined)).toBe(false);
    });

    it('should enforce hyphen restrictions (no leading, trailing, or consecutive)', () => {
        expect(isPIVXName('-alex.pivx')).toBe(false);
        expect(isPIVXName('alex-.pivx')).toBe(false);
        expect(isPIVXName('al--ex.pivx')).toBe(false);
        expect(isPIVXName('al-ex.pivx')).toBe(true);
    });

    it('should enforce length rules', () => {
        expect(isPIVXName('.pivx')).toBe(false);
        expect(isPIVXName('a.pivx')).toBe(true);
        expect(isPIVXName('a'.repeat(59) + '.pivx')).toBe(true); // total length = 64
        expect(isPIVXName('a'.repeat(60) + '.pivx')).toBe(false); // total length = 65
    });

    it('should reject invalid characters', () => {
        expect(isPIVXName('al_ex.pivx')).toBe(false);
        expect(isPIVXName('alex!.pivx')).toBe(false);
        expect(isPIVXName('alex space.pivx')).toBe(false);
    });
});

describe('isPIVXNameTLD', () => {
    it('should return true if name ends with a supported TLD', () => {
        expect(isPIVXNameTLD('alex.pivx')).toBe(true);
        expect(isPIVXNameTLD('test.secure')).toBe(true);
        expect(isPIVXNameTLD('check.safe')).toBe(true);
        expect(isPIVXNameTLD('secret.private')).toBe(true);
        expect(isPIVXNameTLD('upper.PIVX')).toBe(true);
    });

    it('should return false if name does not end with a supported TLD', () => {
        expect(isPIVXNameTLD('alex.pivx2')).toBe(false);
        expect(isPIVXNameTLD('alex.name')).toBe(false);
        expect(isPIVXNameTLD('alex')).toBe(false);
        expect(isPIVXNameTLD('')).toBe(false);
    });
});

describe('PIVXNameTLDs', () => {
    it('should contain the supported TLDs', () => {
        expect(PIVXNameTLDs).toEqual(['.pivx', '.secure', '.safe', '.private']);
    });
});

describe('EVM and Indexer Root Checking', () => {
    beforeEach(() => {
        vi.stubGlobal('fetch', vi.fn());
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    it('should successfully fetch EVM contract root via fetchArbitrumRoot', async () => {
        const mockResponse = {
            result: '0x7fbe8f29f7278db7a665de4f1255927b40b648b43e55b34bb3e0405edb5e7d12'
        };
        fetch.mockResolvedValueOnce({
            ok: true,
            json: async () => mockResponse
        });

        const root = await fetchArbitrumRoot('https://rpc-url', '0xcontract');
        expect(root).toBe('7fbe8f29f7278db7a665de4f1255927b40b648b43e55b34bb3e0405edb5e7d12');
        expect(fetch).toHaveBeenCalledWith('https://rpc-url', expect.objectContaining({
            method: 'POST',
            body: JSON.stringify({
                jsonrpc: '2.0',
                method: 'eth_call',
                params: [
                    {
                        to: '0xcontract',
                        data: '0xfdab463d'
                    },
                    'latest'
                ],
                id: 1
            })
        }));
    });
    it('should successfully fetch indexer SMT root via fetchIndexerRoot', async () => {
        const mockResponse = {
            response: {
                indexer_smt_root: '7FBE8F29F7278DB7A665DE4F1255927B40B648B43E55B34BB3E0405EDB5E7D12'
            }
        };
        fetch.mockResolvedValueOnce({
            ok: true,
            json: async () => mockResponse
        });

        const root = await fetchIndexerRoot('https://indexer-url');
        expect(root).toBe('7fbe8f29f7278db7a665de4f1255927b40b648b43e55b34bb3e0405edb5e7d12');
        expect(fetch).toHaveBeenCalledWith('https://indexer-url/v1.0/info');
    });

    it('should return true if root exists historically on contract via verifyRootValidityOnContract', async () => {
        const mockResponse = {
            result: '0x0000000000000000000000000000000000000000000000000000000000039447' // block height 234567
        };
        fetch.mockResolvedValueOnce({
            ok: true,
            json: async () => mockResponse
        });

        const isValid = await verifyRootValidityOnContract('https://rpc-url', '0xcontract', 'abc');
        expect(isValid).toBe(true);
        expect(fetch).toHaveBeenCalledWith('https://rpc-url', expect.objectContaining({
            method: 'POST',
            body: JSON.stringify({
                jsonrpc: '2.0',
                method: 'eth_call',
                params: [
                    {
                        to: '0xcontract',
                        data: '0x66dd97ab0000000000000000000000000000000000000000000000000000000000000abc'
                    },
                    'latest'
                ],
                id: 1
            })
        }));
    });

    it('should return false if root does not exist on contract via verifyRootValidityOnContract', async () => {
        const mockResponse = {
            result: '0x0000000000000000000000000000000000000000000000000000000000000000' // block height 0
        };
        fetch.mockResolvedValueOnce({
            ok: true,
            json: async () => mockResponse
        });

        const isValid = await verifyRootValidityOnContract('https://rpc-url', '0xcontract', 'abc');
        expect(isValid).toBe(false);
    });
});

describe('PiNS.vue Component', () => {
    beforeEach(async () => {
        vi.useFakeTimers();
        vi.stubGlobal('fetch', vi.fn());
        vi.spyOn(Database, 'getInstance').mockResolvedValue({
            getSettings: async () => ({
                nameResolvingApi: 'https://indexer.pivx.name',
                evmRpc: 'https://evm-rpc.pivx.name',
                evmContractAddress: '0xcontract'
            })
        });
    });


    afterEach(() => {
        vi.restoreAllMocks();
        vi.unstubAllGlobals();
        vi.useRealTimers();
    });

    it('should stop polling and show security warning modal if indexer root becomes invalid during domain not found sync polling', async () => {
        // Mock fetch calls
        // 1. resolve call for getPivxNameRoots
        const resolveResponse = {
            error: { error_message: 'Domain not found' }
        };
        // 2. fetchArbitrumRoot call (currentRoot)
        const evmRootResponse = {
            result: '0x1111000000000000000000000000000000000000000000000000000000000000'
        };
        // 3. fetchIndexerRoot call (v1.0/info) - initial valid root
        const indexerRootResponse1 = {
            response: {
                indexer_smt_root: '2222000000000000000000000000000000000000000000000000000000000000'
            }
        };
        // 4. verifyRootValidityOnContract call (rootHistory for 2222...) - returns block height > 0 (valid)
        const verifyRootResponse1 = {
            result: '0x0000000000000000000000000000000000000000000000000000000000039447'
        };

        // We set up fetch mocks in sequence
        fetch
            // Initial call sequence in resolveAndVerify
            .mockResolvedValueOnce({ ok: true, json: async () => resolveResponse }) // resolve
            .mockResolvedValueOnce({ ok: true, json: async () => evmRootResponse }) // currentRoot
            .mockResolvedValueOnce({ ok: true, json: async () => indexerRootResponse1 }) // info
            .mockResolvedValueOnce({ ok: true, json: async () => verifyRootResponse1 }); // rootHistory

        const wrapper = mount(PiNS);
        
        // Trigger initial resolution
        await wrapper.vm.resolveAndVerify('notfound.pivx', 10, true, '');

        // Verify initial state: polling should be active and modal should be in 'not_found' sync delay state
        expect(wrapper.vm.showSyncModal).toBe(true);
        expect(wrapper.vm.syncModalState).toBe('not_found');
        expect(wrapper.vm.syncModalIsPolling).toBe(true);

        // Now setup fetch mock for the next polling interval tick:
        // indexer returns a wrong invalid root (e.g. 9999...)
        const indexerRootResponse2 = {
            response: {
                indexer_smt_root: '9999000000000000000000000000000000000000000000000000000000000000'
            }
        };
        // verifyRootValidityOnContract for 9999... returns block height 0 (invalid)
        const verifyRootResponse2 = {
            result: '0x0000000000000000000000000000000000000000000000000000000000000000'
        };

        fetch
            .mockResolvedValueOnce({ ok: true, json: async () => resolveResponse }) // resolve
            .mockResolvedValueOnce({ ok: true, json: async () => evmRootResponse }) // currentRoot
            .mockResolvedValueOnce({ ok: true, json: async () => indexerRootResponse2 }) // info
            .mockResolvedValueOnce({ ok: true, json: async () => verifyRootResponse2 }); // rootHistory

        // Advance timers by 5 seconds to trigger one interval tick
        await vi.advanceTimersByTimeAsync(5000);

        // Verify that the polling has stopped and the modal transitions to the security warning 'invalid_root'
        expect(wrapper.vm.syncModalIsPolling).toBe(false);
        expect(wrapper.vm.syncModalState).toBe('invalid_root');
        expect(wrapper.vm.showSyncModal).toBe(true);
    });
});

