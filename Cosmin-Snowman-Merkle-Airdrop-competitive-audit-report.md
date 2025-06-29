# Snowman Merkle Airdrop - Findings Report

# Table of contents
- ## [Contest Summary](#contest-summary)
- ## [Results Summary](#results-summary)
- ## High Risk Findings
    - ### [H-01. [H-3] Unrestricted Public Minting of Snowman NFTs Allows Arbitrary Token Creation](#H-01)
    - ### [H-02. [M-1] Typo in EIP-712 `MESSAGE_TYPEHASH` Prevents Valid Signature Verification](#H-02)
- ## Medium Risk Findings
    - ### [M-01. [M-2] Claim Fails as Live Balance Used for Merkle Verification Mismatches Static Entitlement](#M-01)
- ## Low Risk Findings
    - ### [L-01. [H-1]Replay Attack in `claimSnowman` Allows Multiple NFT Claims Due to Missing `s_hasClaimedSnowman` Check](#L-01)


# <a id='contest-summary'></a>Contest Summary

### Sponsor: First Flight #42

### Dates: Jun 12th, 2025 - Jun 19th, 2025

[See more contest details here](https://codehawks.cyfrin.io/c/2025-06-snowman-merkle-airdrop)

# <a id='results-summary'></a>Results Summary
### Snowman Merkle Airdrop Audit:
📁 Total Submissions: 525

🚨 Unique Vulnerabilities Identified: 5

- 🔴 High: 2

- 🟠 Medium: 1

- 🟡 Low: 2
### Number of findings by me in the contest:
- High: 2/2
- Medium: 1/1
- Low: 1/2


# High Risk Findings

## <a id='H-01'></a>H-01. [H-3] Unrestricted Public Minting of Snowman NFTs Allows Arbitrary Token Creation            



# \[H-3] Unrestricted Public Minting of Snowman NFTs Allows Arbitrary Token Creation

## Description

* **Normal Protocol Behavior:** The `Snowman.sol` contract (ERC721) NFTs are intended to be distributed via the `SnowmanAirdrop.sol` contract. This airdrop contract uses a Merkle tree system. Recipients prove their eligibility, stake their `Snow` tokens into the `SnowmanAirdrop.sol` contract, and in return, the `SnowmanAirdrop.sol` contract is responsible for ensuring they receive Snowman NFTs equal to their staked `Snow` balance. This controlled mechanism is crucial for the NFT's intended distribution and value.

* **Specific Vulnerability:** The `mintSnowman(address receiver, uint256 amount)` function in `Snowman.sol` is declared `external` and lacks any access control. This allows any external account to call it directly and mint an arbitrary number of Snowman NFTs to any address, completely bypassing the `Snow` token staking and Merkle verification process managed by `SnowmanAirdrop.sol`.

```Solidity
// Snowman.sol
contract Snowman is ERC721, Ownable {
    // ...
    function mintSnowman(address receiver, uint256 amount) external { // @> VULNERABILITY: No access control
        for (uint256 i = 0; i < amount; i++) {
            _safeMint(receiver, s_TokenCounter);

            emit SnowmanMinted(receiver, s_TokenCounter);

            s_TokenCounter++;
        }
    }
    // ...
}
```

## Risk

**Likelihood**: High

* An attacker (any external account) can easily discover and call the public `mintSnowman` function.

**Impact**: High

* **Unlimited NFT Supply & Devaluation:** Attackers can mint an unlimited number of Snowman NFTs, destroying their scarcity and value.

* **Circumvention of Airdrop Mechanism:** The intended distribution via `SnowmanAirdrop.sol` (based on Merkle proofs and `Snow` token staking) is rendered ineffective.

* **Unfair Advantage and Market Manipulation:** Attackers can pre-mint NFTs.

* **Loss of User Trust and Project Credibility:** This fundamental flaw damages the project's reputation.

## Proof of Concept

The following Foundry test, `testVulnerability_AttackerCanMintSnowman` from `test/Snowman.t.sol`, demonstrates that an arbitrary `attacker` address can successfully call `mintSnowman`.

```Solidity
// test/Snowman.t.sol
contract TestSnowman is Test {
    Snowman nft;
    // ... other setup variables ...
    address contractOwner;
    address attacker;

    function setUp() public {
        // ... (deployment of Snowman contract and nft initialization) ...
        // Example:
        DeploySnowman deployer = new DeploySnowman();
        nft = deployer.run();
        contractOwner = nft.owner(); // Assuming nft is initialized in setup
        attacker = makeAddr("attacker"); // Creates a distinct address
        assertTrue(attacker != contractOwner, "Attacker should not be the contract owner for this PoC.");
    }

    function testVulnerability_AttackerCanMintSnowman() public {
        uint256 mintAmountByAttacker = 5;
        address receiverForAttackersMint = makeAddr("receiver_for_attackers_mint");

        uint256 initialTotalSupply = nft.getTokenCounter();
        uint256 initialReceiverBalance = nft.balanceOf(receiverForAttackersMint);

        // THE ATTACK: Attacker (who is NOT the owner) calls mintSnowman
        vm.startPrank(attacker);
        nft.mintSnowman(receiverForAttackersMint, mintAmountByAttacker);
        vm.stopPrank();

        uint256 finalTotalSupply = nft.getTokenCounter();
        uint256 finalReceiverBalance = nft.balanceOf(receiverForAttackersMint);

        // Assertions to prove the vulnerability
        assertEq(finalTotalSupply, initialTotalSupply + mintAmountByAttacker, "VULNERABILITY: Total supply should increase by attacker's mintAmount.");
        assertEq(finalReceiverBalance, initialReceiverBalance + mintAmountByAttacker, "VULNERABILITY: Receiver's balance should increase by attacker's mintAmount.");

        uint256 firstTokenIdMintedByAttacker = initialTotalSupply;
        assertEq(nft.ownerOf(firstTokenIdMintedByAttacker), receiverForAttackersMint, "VULNERABILITY: receiverForAttackersMint should own the token minted by the attacker.");
    }
}
```

## Recommended Mitigation

To align with the protocol's described invariants, where `SnowmanAirdrop.sol` manages the eligibility and distribution of Snowman NFTs based on `Snow` token staking and Merkle proofs, the `mintSnowman` function in `Snowman.sol` must be restricted.

The most direct and secure approach is to designate `SnowmanAirdrop.sol` as the **exclusive minter** for `Snowman.sol`.

1. **Modify** **`Snowman.sol`** **to implement a "Minter Role":**

   * Add a state variable to store the address of the authorized `minterContract`.

   * Add a modifier (`onlyMinter`) that restricts the execution of `mintSnowman` to this `minterContract` address.

   * Add an `onlyOwner` function (`setMinter`) to allow the owner of `Snowman.sol` to set the address of the `SnowmanAirdrop.sol` contract as the `minterContract`.

   ```diff
   // Snowman.sol
   contract Snowman is ERC721, Ownable {
       // ...
   +   address public minterContract;
       // ...

   +   event MinterSet(address indexed minter); // Optional: event for when minter is set

   +   modifier onlyMinter() {
   +       if (msg.sender != minterContract) {
   +           revert SM__NotAllowed(); // Or a more specific error like "CallerIsNotMinter"
   +       }
   +       _;
   +   }

   +   // Function to set the Minter contract (callable by Snowman.sol's owner)
   +   function setMinter(address _minter) external onlyOwner {
   +       if (_minter == address(0)) {
   +           revert SM__ZeroAddress(); // Or your preferred zero address error
   +       }
   +       minterContract = _minter;
   +       emit MinterSet(_minter); // Optional
   +   }

   -   function mintSnowman(address receiver, uint256 amount) external {...}
   +   function mintSnowman(address receiver, uint256 amount) external onlyMinter {...}
       // ...
   }
   ```

2. **Operational Flow:**

   * After deploying both `Snowman.sol` and `SnowmanAirdrop.sol`, the owner of `Snowman.sol` calls `setMinter(addressOfSnowmanAirdropContract)` on `Snowman.sol`.

   * When a user (recipient) successfully calls `claimSnowman` (or `claimSnowmanFor`) in `SnowmanAirdrop.sol`:

     * `SnowmanAirdrop.sol` verifies the Merkle proof and signatures (if any).

     * `SnowmanAirdrop.sol` handles the staking of the user's `Snow` tokens.

     * `SnowmanAirdrop.sol` then calls `Snowman.sol::mintSnowman(recipient, verifiedAmount)`, where `verifiedAmount` is the number of NFTs the recipient is entitled to, based on their `Snow` balance from the Merkle proof.

This mitigation ensures:

* The `mintSnowman` function in `Snowman.sol` is no longer publicly callable.

* Only `SnowmanAirdrop.sol`, after its internal verifications (Merkle proof, Snow staking), can trigger the minting of Snowman NFTs.

* This directly implements the README's intent: "Recipients stake their Snow tokens and receive Snowman NFTS equal to their Snow balance in return" via the `SnowmanAirdrop` contract.

## <a id='H-02'></a>H-02. [M-1] Typo in EIP-712 `MESSAGE_TYPEHASH` Prevents Valid Signature Verification            



# \[M-1] Typo in EIP-712 `MESSAGE_TYPEHASH` Prevents Valid Signature Verification

## Description

* **Normal Protocol Behavior:** The `SnowmanAirdrop.sol` contract uses EIP-712 signatures to authorize claims, allowing a third party (like "satoshi" in the tests) to submit a claim on behalf of a `receiver` if they provide a valid signature from the `receiver`. The signature is generated over a hash of a `SnowmanClaim` struct, which includes the `receiver`'s address and their `amount` of `Snow` tokens.

* **Specific Issue:** The `MESSAGE_TYPEHASH` constant, used to construct the EIP-712 typed data hash, contains a typographical error. The `receiver` field is misspelled as "addre**s**" instead of "addre**ss**".

  ```solidity
  bytes32 private constant MESSAGE_TYPEHASH = keccak256("SnowmanClaim(addres receiver, uint256 amount)");
  ```

  This means that the hash computed by the contract for signature verification will be different from the hash computed by any standard EIP-712 compliant client or library that uses the correct struct definition: `SnowmanClaim(address receiver, uint256 amount)`. As a result, valid signatures generated by users/clients will not match the contract's expectation, causing all such `claimSnowman` calls to fail with `SA__InvalidSignature`.

## Risk

**Likelihood**: High

* Any attempt to use the `claimSnowman` function with a signature generated by a standard EIP-712 compliant method (which would use the correct spelling) will fail.

**Impact**: Medium

* **Functionality Breakdown:** The primary mechanism for delegated claims (`claimSnowman` when `msg.sender != receiver`) is broken. Users who intend to have a third party submit their claim transaction will be unable to do so.

* **User Frustration:** Users attempting to use this feature will encounter unexpected failures.

* **Deviation from Standard:** The contract does not correctly implement the EIP-712 standard for the specified struct due to the typo, undermining interoperability and trust in the signature scheme.
  *(Note: If* *`claimSnowman`* *is also intended to be called directly by the* *`receiver`* *themselves providing their own signature, that path would also be broken for the same reason.)*

## Proof of Concept

Add `testTypoInMessageTypehash_PreventsCorrectClientSignatureValidation` function in `test/SnowmanAirdrop.t.sol `:

1. Mints 1 `Snow` token to "alice".
2. Alice approves the `SnowmanAirdrop` contract.
3. It then manually constructs an EIP-712 digest (`correctDigestToSign`) using the **correct** type string: `"SnowmanClaim(address receiver,uint256 amount)"`.
4. Alice signs this `correctDigestToSign`.
5. "satoshi" attempts to call `claimSnowman` on behalf of Alice using this signature and Alice's valid Merkle proof.
6. The call is expected to, and does, revert with `SA__InvalidSignature`. This is because the `SnowmanAirdrop` contract, due to the typo in its internal `MESSAGE_TYPEHASH`, calculates a different expected digest.

```Solidity
// test/SnowmanAirdrop.t.sol
function testTypoInMessageTypehash_PreventsCorrectClientSignatureValidation()
    public
{
    // Alice is one of the default users set up by Helper.s.sol with 1 Snow token.
    assertEq(snow.balanceOf(alice), 1);

    // Alice approves the airdrop contract for her 1 Snow token
    vm.prank(alice);
    snow.approve(address(airdrop), 1);

    uint256 amountForSignature = 1; // This is i_snow.balanceOf(alice) for the test

    // 1. Manually construct the EIP-712 struct hash with the CORRECT type string
    bytes32 CORRECT_MESSAGE_TYPEHASH = keccak256(
        bytes("SnowmanClaim(address receiver,uint256 amount)")
    );
    bytes32 correctStructHash = keccak256(
        abi.encode(
            CORRECT_MESSAGE_TYPEHASH,
            alice, // receiver
            amountForSignature // amount
        )
    );

    // 2. Manually construct the full EIP-712 digest
    bytes32 EIP712DOMAIN_TYPEHASH = keccak256(
        bytes(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        )
    );
    bytes32 calculatedDomainSeparator = keccak256(
        abi.encode(
            EIP712DOMAIN_TYPEHASH,
            keccak256(bytes("Snowman Airdrop")),
            keccak256(bytes("1")),
            block.chainid,
            address(airdrop)
        )
    );
    bytes32 correctDigestToSign = keccak256(
        abi.encodePacked(
            "\x19\x01", // EIP-191 prefix
            calculatedDomainSeparator,
            correctStructHash
        )
    );

    // 3. Alice signs this CORRECTLY computed digest
    (uint8 alV_correct, bytes32 alR_correct, bytes32 alS_correct) = vm.sign(
        alKey,
        correctDigestToSign
    );

    // 4. Satoshi attempts to claim for Alice using this "correct client" signature
    console2.log(
        "Attempting claim with signature based on CORRECT type string..."
    );
    vm.prank(satoshi);
    vm.expectRevert(SnowmanAirdrop.SA__InvalidSignature.selector);
    airdrop.claimSnowman(
        alice,
        AL_PROOF, // Assumes AL_PROOF is a valid Merkle proof for Alice
        alV_correct,
        alR_correct,
        alS_correct
    );

    // 5. For comparison, get the digest the contract *would* compute
    bytes32 digestFromContractViaGetter = airdrop.getMessageHash(alice);
    assertNotEq(
        correctDigestToSign,
        digestFromContractViaGetter,
        "Digest from correct type string should differ from contract's typo-based digest."
    );
//if we reached this, that means the test passed.
    console2.log(
        "TEST PASSED: Claim with a signature based on the *correct* EIP-712 type string was REJECTED."
    );
}
```

The test confirms that a signature generated based on the correct EIP-712 struct definition fails verification due to the contract's internal typo.

## Recommended Mitigation

Correct the typographical error in the `MESSAGE_TYPEHASH` constant within the `SnowmanAirdrop.sol` contract.

Change:

```diff
-    bytes32 private constant MESSAGE_TYPEHASH = keccak256("SnowmanClaim(addres receiver, uint256 amount)");
+    bytes32 private constant MESSAGE_TYPEHASH = keccak256("SnowmanClaim(address receiver,uint256 amount)");
```

This will ensure that the contract computes the EIP-712 hash consistent with standard client implementations, allowing valid signatures to be correctly verified.

    
# Medium Risk Findings

## <a id='M-01'></a>M-01. [M-2] Claim Fails as Live Balance Used for Merkle Verification Mismatches Static Entitlement            



# \[M-2] Claim Fails as Live Balance Used for Merkle Verification Mismatches Static Entitlement

## Description

* The `SnowmanAirdrop` contract enables users, defined in a Merkle tree with specific claim amounts, to receive `Snowman` NFTs by staking their `Snow` tokens. Claims can be authorized via EIP-712 signatures.

* The `claimSnowman` function and its helper `getMessageHash` incorrectly use the user's *live/current* `Snow` token balance to determine the `amount` for both EIP-712 signature validation and for constructing the Merkle leaf during on-chain proof verification. This causes a mismatch if the user's live balance differs from the static `amount` defined for them in the Merkle tree, leading to valid claims failing.

```solidity
// Contract: SnowmanAirdrop.sol

function claimSnowman(address receiver, bytes32[] calldata merkleProof, uint8 v, bytes32 r, bytes32 s) /* ... */ {
    // ...
    if (!_isValidSignature(receiver, getMessageHash(receiver), v, r, s)) { // @> Uses getMessageHash which relies on live balance
        revert SA__InvalidSignature();
    }

@>  uint256 amount = i_snow.balanceOf(receiver); // @> Amount for leaf is derived from live balance
@>  bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(receiver, amount)))); // @> Leaf constructed with live balance

    if (!MerkleProof.verify(merkleProof, i_merkleRoot, leaf)) { // @> Proof for static amount fails against leaf from live balance
        revert SA__InvalidProof();
    }
    // ...
}

function getMessageHash(address receiver) public view returns (bytes32) {
    // ...
@>  uint256 amount = i_snow.balanceOf(receiver); // @> Amount for signature based on live balance
    return _hashTypedDataV4( /* ... SnowmanClaim({receiver: receiver, amount: amount}) ... */ );
}
```

## Risk

**Likelihood**: Medium

* Users' token balances are expected to change due to normal blockchain activities (earning, buying, transfers).

* The claim mechanism's reliance on this live balance for critical verification data makes discrepancies with the Merkle tree's static entitlement highly probable.

**Impact**: Medium

* Eligible users are unable to claim their airdropped NFTs if their live `Snow` balance deviates from their static Merkle tree entitlement, as Merkle proof verification will incorrectly fail.

* The airdrop's intended distribution is impaired, diminishing its effectiveness and fairness, and resulting in a negative user experience.

## Proof of Concept

    1. Alice's Merkle tree entitlement: 1 Snow. Initial balance matches. 

    2. Alice's Snow balance increases to 2 (newLiveBalance) via snow\.earnSnow().

    3. Signature is generated for Alice based on newLiveBalance (2 Snow).

    4. claimSnowman is called with Alice's original Merkle proof (for 1 Snow)
// and the signature (for 2 Snow).

    5. Result: Signature check passes. Merkle leaf constructed with newLiveBalance (2 Snow).
// MerkleProof.verify fails as proof is for 1       Snow. Reverts SA\_\_InvalidProof.

Add the following test to `test/TestSnowmanAirdrop.t.sol` :

```Solidity
function testClaimFailsWhenLiveBalanceDiffersFromMerkleTreeAmount() public {
        uint256 merkleTreeEntitlementAmount = 1;
        assertEq(snow.balanceOf(alice), merkleTreeEntitlementAmount);

        vm.warp(block.timestamp + 1 weeks + 1 seconds); // Allow earning again
        vm.prank(alice);
        snow.earnSnow(); // Alice's balance increases to 2
        uint256 newLiveBalance = snow.balanceOf(alice);

        vm.prank(alice);
        bytes32 digest = airdrop.getMessageHash(alice); // Uses newLiveBalance (2) for signature
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alKey, digest);

        vm.prank(alice);
        snow.approve(address(airdrop), newLiveBalance);

        vm.prank(satoshi); // Another address attempts claim for Alice
        vm.expectRevert(SnowmanAirdrop.SA__InvalidProof.selector);
        // AL_PROOF is for merkleTreeEntitlementAmount (1)
        airdrop.claimSnowman(alice, AL_PROOF, v, r, s);
    }

```

## Recommended Mitigation

Considering the issue where the user's live balance can cause discrepancies with their static Merkle tree entitlement, I suggest modifying the claim process to explicitly use the `entitledAmount` (the fixed amount from the Merkle tree data) as the basis for all verification steps and token operations. This involves passing the `entitledAmount` as a parameter to the `claimSnowman` function and using it consistently for EIP-712 signature generation, Merkle leaf construction, and the actual token transfer and minting amounts. This approach ensures that claim validity is tied directly to the immutable Merkle tree data, rather than a user's potentially volatile live balance.

```diff
// File: src/SnowmanAirdrop.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ... imports ...

contract SnowmanAirdrop is EIP712, ReentrancyGuard {
    // ... (errors, other struct members, variables) ...
+   error SA__InsufficientSnowBalanceForClaim();
+   error SA__AlreadyClaimed(); // Recommended from H-1 (Replay Attack)

    struct SnowmanClaim {
        address receiver;
-        uint256 amount;
+        uint256 entitledAmount; // Use the static amount from Merkle tree
    }

-    bytes32 private constant MESSAGE_TYPEHASH = keccak256("SnowmanClaim(addres receiver, uint256 amount)");
+    // Corrected typo (addres -> address) and field name (amount -> entitledAmount)
+    bytes32 private constant MESSAGE_TYPEHASH = keccak256("SnowmanClaim(address receiver,uint256 entitledAmount)");


    function claimSnowman(
        address receiver,
+       uint256 entitledAmount, // Pass the static entitled amount
        bytes32[] calldata merkleProof,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external nonReentrant {
+       if (s_hasClaimedSnowman[receiver]) { // Prevent re-claims (H-1 mitigation)
+           revert SA__AlreadyClaimed();
+       }
        if (receiver == address(0)) {
            revert SA__ZeroAddress();
        }
+       if (entitledAmount == 0) { // Check the entitlement itself
+           revert SA__ZeroAmount();
+       }
+
+       // Ensure user has enough Snow to cover their static entitlement
+       if (i_snow.balanceOf(receiver) < entitledAmount) {
+           revert SA__InsufficientSnowBalanceForClaim();
+       }

-       if (!_isValidSignature(receiver, getMessageHash(receiver), v, r, s)) {
+       // Validate signature against the static entitledAmount
+       if (!_isValidSignature(receiver, getMessageHash(receiver, entitledAmount), v, r, s)) {
            revert SA__InvalidSignature();
        }

-       uint256 amount = i_snow.balanceOf(receiver); // No longer use live balance here
-       bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(receiver, amount))));
+       // Construct leaf using the static entitledAmount
+       bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(receiver, entitledAmount))));

        if (!MerkleProof.verify(merkleProof, i_merkleRoot, leaf)) {
            revert SA__InvalidProof();
        }

-       i_snow.safeTransferFrom(receiver, address(this), amount);
+       // Transfer the static entitledAmount
+       i_snow.safeTransferFrom(receiver, address(this), entitledAmount);

        s_hasClaimedSnowman[receiver] = true;

-       emit SnowmanClaimedSuccessfully(receiver, amount);
+       emit SnowmanClaimedSuccessfully(receiver, entitledAmount);

-       i_snowman.mintSnowman(receiver, amount);
+       i_snowman.mintSnowman(receiver, entitledAmount);
    }

    // ... _isValidSignature remains the same ...

-   function getMessageHash(address receiver) public view returns (bytes32) {
-       uint256 amount = i_snow.balanceOf(receiver); // No longer use live balance
+   // getMessageHash now takes the static entitledAmount
+   function getMessageHash(address receiver, uint256 entitledAmount) public view returns (bytes32) {
        return _hashTypedDataV4(
-            keccak256(abi.encode(MESSAGE_TYPEHASH, SnowmanClaim({receiver: receiver, amount: amount})))
+            keccak256(abi.encode(MESSAGE_TYPEHASH, SnowmanClaim({receiver: receiver, entitledAmount: entitledAmount})))
        );
    }
    // ... other functions ...
}
```


# Low Risk Findings

## <a id='L-01'></a>L-01. [H-1]Replay Attack in `claimSnowman` Allows Multiple NFT Claims Due to Missing `s_hasClaimedSnowman` Check            



# \[H-1]Replay Attack in `claimSnowman` Allows Multiple NFT Claims Due to Missing `s_hasClaimedSnowman` Check

## Description

* **Normal Behavior:** The `SnowmanAirdrop` contract is designed to allow eligible users (those included in a Merkle tree and possessing the required Snow tokens) to claim a Snowman NFT a single time. The `claimSnowman` function validates a user's Merkle proof and their signature, transfers their Snow tokens to the contract, mints them an NFT, and then records that the user has claimed by setting `s_hasClaimedSnowman[receiver]` to `true`.

* **Specific Issue:** The `claimSnowman` function does not check the `s_hasClaimedSnowman[receiver]` status at the beginning of the function call. If a user re-acquires the exact same amount of Snow tokens they used for their initial successful claim, the original (and previously valid) signature and Merkle proof can be re-submitted by anyone. This allows the user to claim NFTs multiple times, bypassing the intended one-claim-per-user mechanism.

```Solidity
// SnowmanAirdrop.sol
    function claimSnowman(address receiver, bytes32[] calldata merkleProof, uint8 v, bytes32 r, bytes32 s)
        external
        nonReentrant
    {
        // @> VULNERABILITY: Missing check for s_hasClaimedSnowman[receiver] == true at the beginning.
        // @> An early revert here would prevent the replay.

        if (receiver == address(0)) {
            revert SA__ZeroAddress();
        }
        // @> This check can be passed again if the user re-acquires the exact token amount.
        if (i_snow.balanceOf(receiver) == 0) {
            revert SA__ZeroAmount();
        }

        // @> The signature check can pass again with the same signature if getMessageHash(receiver)
        // @> returns the same hash. This happens if the receiver's Snow balance is restored
        // @> to the exact amount it was when the original signature was created.
        if (!_isValidSignature(receiver, getMessageHash(receiver), v, r, s)) {
            revert SA__InvalidSignature();
        }

        uint256 amount = i_snow.balanceOf(receiver);

        // @> The Merkle proof check can also pass again with the same proof if the leaf
        // @> (which depends on 'receiver' and 'amount') is reconstructed to be the same.
        // @> This occurs if 'amount' (from i_snow.balanceOf(receiver)) is the same as the original claim.
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(receiver, amount))));

        if (!MerkleProof.verify(merkleProof, i_merkleRoot, leaf)) {
            revert SA__InvalidProof();
        }

        i_snow.safeTransferFrom(receiver, address(this), amount); // send tokens to contract... akin to burning

        s_hasClaimedSnowman[receiver] = true; // @> This flag is set, but only AFTER all checks have passed again,
                                             // @> thus not preventing the current replay.

        emit SnowmanClaimedSuccessfully(receiver, amount);

        i_snowman.mintSnowman(receiver, amount);
    }
    // ...
}
```

## Risk

**Likelihood**: High

* A legitimate user successfully claims their Snowman NFT using their signature and a valid Merkle proof.

* The same user re-acquires the exact quantity of Snow tokens they staked for the initial claim (e.g., via the `earnSnow()` function in `Snow.sol` after the cooldown, by purchasing more, or receiving a transfer).

* The original signature and Merkle proof (which are now valid again because the user's Snow balance matches the state at the time of original signing and Merkle leaf generation) are re-submitted to the `claimSnowman` function by any party (the user themselves or a third party like "satoshi" in the test).

**Impact**: High

* **Unintended NFT Inflation & Value Dilution:** Users can exploit this to mint more Snowman NFTs than they are entitled to according to the Merkle airdrop rules. This inflates the NFT supply beyond what was intended, potentially devaluing the NFTs for all holders.

* **Compromise of Airdrop Fairness:** The core principle of a Merkle airdrop is to ensure a fair, one-time distribution to a specific set of users with specific allocations. This vulnerability breaks that fairness, allowing some users to receive multiple allocations.

* **Excessive Token Staking/Burning:** The Snow tokens intended to be staked (and effectively burned or locked in the airdrop contract) are processed multiple times for the same original entitlement, leading to more tokens being removed from the user's control and sent to the airdrop contract than designed.

## Proof of Concept

The following test case from `TestSnowmanAirdrop.t.sol` demonstrates the replay attack. Alice successfully claims an NFT, then re-acquires the necessary Snow tokens, and the original claim data is used to claim a second NFT for her.

```Solidity
function testReplayAttackOnClaimSnowman() public {
     
        // --- Alice's First Successful Claim ---
        assertEq(snow.balanceOf(alice), 1, "PRE-REQ: Alice should have 1 wei Snow before first claim");
        uint256 initialAirdropSnowBalance = snow.balanceOf(address(airdrop));
        uint256 initialAliceNftId = nft.getTokenCounter(); // Get token ID before minting for Alice

        vm.prank(alice);
        snow.approve(address(airdrop), 1); // Alice approves 1 wei

        // Generate signature based on Alice's current state (balance of 1 wei)
        bytes32 alDigestOriginal = airdrop.getMessageHash(alice);
        (uint8 alV, bytes32 alR, bytes32 alS) = vm.sign(alKey, alDigestOriginal);

        vm.prank(satoshi); // Satoshi makes the claim for Alice
        airdrop.claimSnowman(alice, AL_PROOF, alV, alR, alS);

        // Assertions for the first successful claim
        assertEq(nft.balanceOf(alice), 1);// Alice should have 1 NFT after first claim
        assertEq(snow.balanceOf(alice), 0); // Alice's Snow balance should be 0 after first claim
        assertTrue(airdrop.getClaimStatus(alice)); // Claim status should be true after successful claim
        assertEq(nft.ownerOf(initialAliceNftId), alice); // Alice should own the newly minted NFT
        assertEq(snow.balanceOf(address(airdrop)), initialAirdropSnowBalance + 1); // Airdrop contract Snow balance should increase by 1

        // --- Setup for Replay Attack ---
        // 1. Alice needs to re-acquire 1 wei of Snow token.
        //    The `earnSnow()` function mints 1 wei but has a timer. We'll advance time.
        vm.warp(block.timestamp + 1 weeks + 1 seconds); // Advance time to bypass earnSnow timer

        vm.prank(alice);
        snow.earnSnow(); // Alice calls earnSnow() to get 1 wei of Snow token again.

        assertEq(snow.balanceOf(alice), 1, "Alice's Snow balance should be 1 wei again for replay attempt");

        // 2. Alice needs to approve the Airdrop contract again for the new tokens.
        vm.prank(alice);
        snow.approve(address(airdrop), 1);

        // --- Attempt Replay Attack ---
        // Satoshi attempts to replay the claim using the *exact same original signature* (alV, alR, alS)
        // and the *exact same Merkle proof* (AL_PROOF).
        // The `getMessageHash(alice)` will now produce the same digest as `alDigestOriginal` because
        // Alice's Snow balance is 1 wei again, which is what the original signature was based on.
        // The Merkle leaf calculation inside `claimSnowman` will also match the original leaf for AL_PROOF.

        bytes32 alDigestForReplay = airdrop.getMessageHash(alice);
        assertEq(alDigestForReplay, alDigestOriginal, "Digest for replay should match original digest if balance is restored");

        uint256 nftBalanceBeforeReplay = nft.balanceOf(alice);
        uint256 snowBalanceOfAliceBeforeReplay = snow.balanceOf(alice);
        uint256 airdropSnowBalanceBeforeReplayAttempt = snow.balanceOf(address(airdrop));
        uint256 nextNftId = nft.getTokenCounter();

        vm.prank(satoshi); // Satoshi makes the replay call
        airdrop.claimSnowman(alice, AL_PROOF, alV, alR, alS);

        // --- Assertions for Successful Replay (Proving Vulnerability) ---
        // If the replay is successful, Alice will have another NFT, and her Snow balance will be 0 again.
        assertEq(nft.balanceOf(alice), nftBalanceBeforeReplay + 1, "VULNERABILITY: Alice received an additional NFT due to replay!");
        assertEq(snow.balanceOf(alice), snowBalanceOfAliceBeforeReplay - 1, "VULNERABILITY: Alice's Snow balance decreased again due to replay!");
        assertEq(nft.ownerOf(nextNftId), alice, "VULNERABILITY: Alice should own the second NFT from replay");
        assertTrue(airdrop.getClaimStatus(alice), "Alice's claim status remains true"); // This flag was set but not checked to prevent replay
        assertEq(snow.balanceOf(address(airdrop)), airdropSnowBalanceBeforeReplayAttempt + 1, "VULNERABILITY: Airdrop contract Snow balance increased again from replay");
    }
```

## Recommended Mitigation

Add a check at the beginning of the `claimSnowman` function to ensure that the `receiver` has not already claimed their NFT. This can be done by checking the `s_hasClaimedSnowman[receiver]` mapping.

```diff
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ... imports ...

contract SnowmanAirdrop is EIP712, ReentrancyGuard {
    using SafeERC20 for Snow;

    // >>> ERRORS
    error SA__InvalidProof();
    error SA__InvalidSignature();
    error SA__ZeroAddress();
    error SA__ZeroAmount();
+   error SA__AlreadyClaimed(); // Add new error for already claimed

    // ... (struct, variables, event, constructor) ...
    mapping(address => bool) private s_hasClaimedSnowman;


    function claimSnowman(address receiver, bytes32[] calldata merkleProof, uint8 v, bytes32 r, bytes32 s)
        external
        nonReentrant
    {
+       if (s_hasClaimedSnowman[receiver]) {
+           revert SA__AlreadyClaimed();
+       }
        if (receiver == address(0)) {
            revert SA__ZeroAddress();
        }
        if (i_snow.balanceOf(receiver) == 0) {
            revert SA__ZeroAmount();
        }

        if (!_isValidSignature(receiver, getMessageHash(receiver), v, r, s)) {
            revert SA__InvalidSignature();
        }

        uint256 amount = i_snow.balanceOf(receiver);

        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(receiver, amount))));

        if (!MerkleProof.verify(merkleProof, i_merkleRoot, leaf)) {
            revert SA__InvalidProof();
        }

        i_snow.safeTransferFrom(receiver, address(this), amount);

        s_hasClaimedSnowman[receiver] = true;

        emit SnowmanClaimedSuccessfully(receiver, amount);

        i_snowman.mintSnowman(receiver, amount);
    }

    // ... (internal functions, public view functions, getter functions) ...
}
```

This mitigation ensures that once a user has successfully claimed, any subsequent attempts to claim for the same `receiver` address will be immediately rejected, regardless of whether other conditions (like token balance or signature validity) might appear to be met again.



