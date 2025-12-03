# Last Man Standing - Findings Report

# Table of contents
- ## [Contest Summary](#contest-summary)
- ## [Results Summary](#results-summary)

- ## Medium Risk Findings
    - ### [M-01. [H-1] Flaw in claimThrone Renders Game Unplayable](#M-01)
    - ### [M-02. [M-1]Missing Payout to Previous King Contradicts Game Rules](#M-02)
    - ### [M-03. [L-1] Unreachable Code in Fee Distribution Logic](#M-03)



# <a id='contest-summary'></a>Contest Summary

### Sponsor: First Flight #45

### Dates: Jul 31st, 2025 - Aug 7th, 2025

[See more contest details here](https://codehawks.cyfrin.io/c/2025-07-last-man-standing)

# <a id='results-summary'></a>Results Summary

### Number of findings:
- High: 0
- Medium: 3
- Low: 0



    
# Medium Risk Findings

## <a id='M-01'></a>M-01. [H-1] Flaw in claimThrone Renders Game Unplayable            



# \[H-1] Flaw in claimThrone Renders Game Unplayable

## Description

The `claimThrone` function is intended to allow a new player to become the `currentKing` by paying a fee. This is the central mechanic of the game, allowing for a "King of the Hill" style competition.

The core logic of the `claimThrone` function contains an inverted `require` statement. Instead of checking that the claimant is *not* the current king, it checks that the claimant *is* the current king. Since the game starts with `currentKing` as `address(0)`, this check always fails for the first player, preventing anyone from ever becoming king and freezing the game in its initial state.

```Solidity
// src/Game.sol

function claimThrone() external payable gameNotEnded nonReentrant {
    require(msg.value >= claimFee, "Game: Insufficient ETH sent to claim the throne.");
@>  require(msg.sender == currentKing, "Game: You are already the king. No need to re-claim.");

    uint256 sentAmount = msg.value;
    uint256 previousKingPayout = 0;
// ...
```

## Risk

**Likelihood**: **High**

* This bug occurs on the very first attempt to call `claimThrone` in any game round.

* It is a certainty that every deployed instance of this contract is immediately and permanently unplayable.

**Impact**: **High**

* The contract's core functionality is completely broken. No player can ever become the king, and the game cannot proceed past its initial state.

* The contract fails to serve its purpose, leading to a total loss of user trust and a failure of the application.

## Proof of Concept

The following Foundry test simulates a full game lifecycle and proves that the game is stuck from the beginning. It shows that the first player's attempt to claim the throne is reverted, the `currentKing` is never updated, and as a result, a winner can never be declared.

```Solidity
// test/Game.t.sol

function testGameStuckKingNotUpdated() public {
    console2.log("--- Test Start: Verifying game is stuck ---");

    // --- Step 1: Player 1 attempts to claim the throne and fails ---
    console2.log("Attempting Player 1 claim...");
    vm.startPrank(player1);
    vm.expectRevert("Game: You are already the king. No need to re-claim.");
    game.claimThrone{value: INITIAL_CLAIM_FEE}();
    vm.stopPrank();
    console2.log("Player 1 claim correctly reverted.");

    // --- Step 2: Verify that the king was NOT updated ---
    // This is the core of the issue. The king should be player1, but is still address(0).
    assertEq(game.currentKing(), address(0), "BUG CONFIRMED: currentKing should be player1, but is address(0)");
    console2.log("Verified currentKing is still address(0).");

    // --- Step 3: Advance time far beyond the grace period ---
    console2.log("Warping time forward by", GRACE_PERIOD + 1, "seconds...");
    vm.warp(block.timestamp + GRACE_PERIOD + 1);
    console2.log("Time advanced.");

    // --- Step 4: Attempt to declare a winner ---
    // This will fail because `currentKing` is `address(0)`.
    // The game is now permanently stuck. No one can claim, and no winner can be declared.
    console2.log("Attempting to declare a winner...");
    vm.prank(player3); // Anyone can try to declare.
    vm.expectRevert("Game: No one has claimed the throne yet.");
    game.declareWinner();
    console2.log("declareWinner correctly reverted because no one ever became king.");
    assertEq(game.currentKing(), address(0), "BUG CONFIRMED: currentKing should still be address(0) after declareWinner attempt");
    console2.log("--- Test End: Confirmed game is permanently stuck ---");
}
```

## Recommended Mitigation

The logical operator in the `require` statement within the `claimThrone` function must be inverted from `==` to `!=`. This ensures that a player can only claim the throne if they are not already the current king.

```diff
// src/Game.sol

function claimThrone() external payable gameNotEnded nonReentrant {
    require(msg.value >= claimFee, "Game: Insufficient ETH sent to claim the throne.");
-   require(msg.sender == currentKing, "Game: You are already the king. No need to re-claim.");
+   require(msg.sender != currentKing, "Game: You are already the king. No need to re-claim.");

    uint256 sentAmount = msg.value;
    uint256 previousKingPayout = 0;
```

## <a id='M-02'></a>M-02. [M-1]Missing Payout to Previous King Contradicts Game Rules            



## \[M-1] Missing Payout to Previous King Contradicts Game Rules

### Description

The game's rules, as described in the function comments, state that when a player claims the throne, a portion of their fee should be paid out to the previous king. This creates a key incentive for players to participate and become the king.

The `claimThrone` function fails to implement this payout mechanic. The `previousKingPayout` variable is initialized to `0` and is never updated. As a result, the overthrown king receives nothing, which is contrary to the documented behavior.

```solidity
// src/Game.sol

function claimThrone() external payable gameNotEnded nonReentrant {
    require(msg.value >= claimFee, "Game: Insufficient ETH sent to claim the throne.");
    require(msg.sender != currentKing, "Game: You are already the king. No need to re-claim.");

    uint256 sentAmount = msg.value;
@>  uint256 previousKingPayout = 0; // Payout is initialized to 0...
    uint256 currentPlatformFee = 0;
    uint256 amountToPot = 0;

    // ... and is never updated before being used in calculations.
    currentPlatformFee = (sentAmount * platformFeePercentage) / 100;

    if (currentPlatformFee > (sentAmount - previousKingPayout)) {
        currentPlatformFee = sentAmount - previousKingPayout;
    }
// ...
```

### Risk

**Likelihood**: **High**

* This bug occurs every time a king is overthrown (assuming the first critical bug is fixed).

* The payout logic is completely absent, so it will fail in 100% of eligible scenarios.

**Impact**: **Medium**

* The game's incentive structure is broken. Players are not rewarded as promised by the rules, which can discourage participation.

* This discrepancy between documented rules and actual contract behavior erodes user trust and the perceived fairness of the game.

### Proof of Concept

The following test first fixes the initial `claimThrone` bug, then proves that `player1` (the overthrown king) receives no payout after `player2` claims the throne. `player1`'s balance remains unchanged throughout the entire process.

```Solidity
// test/Game.t.sol

function testOverthrownKingReceivesNoPayoutThroughoutGameLifecycle() public {
    // This test requires the contract to be fixed so a new player can claim the throne.
    // For this PoC, we assume `require(msg.sender != currentKing)` is in place.

    // Step 1: Player 1 becomes the first king.
    vm.prank(player1);
    game.claimThrone{value: INITIAL_CLAIM_FEE}();
    assertEq(game.currentKing(), player1, "Player 1 should be the king.");

    // Step 2: Record player1's balance before being overthrown.
    uint256 player1BalanceBeforeOverthrow = player1.balance;

    // Step 3: Player 2 overthrows player1.
    uint256 nextClaimFee = game.claimFee();
    vm.prank(player2);
    game.claimThrone{value: nextClaimFee}();
    assertEq(game.currentKing(), player2, "Player 2 should now be the king.");

    // Step 4: Check player1's balance immediately after being overthrown.
    // It should be unchanged, proving no immediate payout was sent.
    assertEq(
        player1.balance,
        player1BalanceBeforeOverthrow,
        "FAIL: Player 1's balance changed immediately after being overthrown."
    );
}
```

### Recommended Mitigation

Implement the payout logic for the previous king. This involves adding a new state variable, `previousKingPayoutPercentage`, to define the payout amount and modifying the `claimThrone` function to calculate and transfer the funds.

```diff
// src/Game.sol

contract Game is Ownable {
    // ...
    uint256 public feeIncreasePercentage;
    uint256 public platformFeePercentage;
+   uint256 public previousKingPayoutPercentage; // Percentage of claimFee for the previous king

    // ...

    constructor(
        uint256 _initialClaimFee,
        uint256 _gracePeriod,
        uint256 _feeIncreasePercentage,
-       uint256 _platformFeePercentage
+       uint256 _platformFeePercentage,
+       uint256 _previousKingPayoutPercentage
    ) Ownable(msg.sender) {
        // ...
        require(_platformFeePercentage <= 100, "Game: Platform fee percentage must be 0-100.");
+       require(_previousKingPayoutPercentage < 100, "Game: Payout percentage must be less than 100.");
+       require((_platformFeePercentage + _previousKingPayoutPercentage) < 100, "Game: Combined fees must be less than 100.");

        // ...
        platformFeePercentage = _platformFeePercentage;
+       previousKingPayoutPercentage = _previousKingPayoutPercentage;

        // ...
    }

    function claimThrone() external payable gameNotEnded nonReentrant {
        require(msg.value >= claimFee, "Game: Insufficient ETH sent to claim the throne.");
        require(msg.sender != currentKing, "Game: You are already the king. No need to re-claim.");

        uint256 sentAmount = msg.value;
-       uint256 previousKingPayout = 0;
-       uint256 currentPlatformFee = 0;
-       uint256 amountToPot = 0;
+       address previousKing = currentKing;
+
+       // Calculate payouts
+       uint256 currentPlatformFee = (sentAmount * platformFeePercentage) / 100;
+       uint256 previousKingPayout = (sentAmount * previousKingPayoutPercentage) / 100;
+
+       // Update platform fee balance
+       platformFeesBalance += currentPlatformFee;
+
+       // Pay the previous king if one exists
+       if (previousKing != address(0) && previousKingPayout > 0) {
+           (bool success, ) = payable(previousKing).call{value: previousKingPayout}("");
+           require(success, "Game: Failed to pay previous king.");
+       }
+
+       // Remaining amount goes to the pot
+       uint256 amountToPot = sentAmount - currentPlatformFee - previousKingPayout;
+       pot += amountToPot;

-       // Calculate platform fee
-       currentPlatformFee = (sentAmount * platformFeePercentage) / 100;
-
-       // Defensive check to ensure platformFee doesn't exceed available amount after previousKingPayout
-       if (currentPlatformFee > (sentAmount - previousKingPayout)) {
-           currentPlatformFee = sentAmount - previousKingPayout;
-       }
-       platformFeesBalance = platformFeesBalance + currentPlatformFee;
-
-       // Remaining amount goes to the pot
-       amountToPot = sentAmount - currentPlatformFee;
-       pot = pot + amountToP
        // Update game state
        currentKing = msg.sender;
        lastClaimTime = block.timestamp;
// ...
```

## <a id='M-03'></a>M-03. [L-1] Unreachable Code in Fee Distribution Logic            



## \[L-1] Unreachable Code in Fee Distribution Logic

### Description

The `claimThrone` function contains logic to distribute the incoming `msg.value` between the contract's `pot` and the `platformFeesBalance`. This logic includes a "defensive" `if` statement intended to prevent the platform fee from exceeding the available amount.

However, due to the surrounding logic, this `if` statement is unreachable. The check `if (currentPlatformFee > (sentAmount - previousKingPayout))` can never evaluate to true because `previousKingPayout` is hardcoded to `0`(because it is never calculated as previously presented in another finding) and `currentPlatformFee` (calculated as a percentage of `sentAmount`) can never be greater than `sentAmount`. This dead code makes the function confusing and indicates a potential misunderstanding of the intended fee distribution mechanism.

```Solidity
// src/Game.sol

function claimThrone() external payable gameNotEnded nonReentrant {
    // ...
    uint256 sentAmount = msg.value;
    uint256 previousKingPayout = 0; // Always 0
//...
@>  // Defensive check to ensure platformFee doesn't exceed available amount after previousKingPayout
@>  // This block is unreachable because `currentPlatformFee` can never be > `sentAmount`.
@>  if (currentPlatformFee > (sentAmount - previousKingPayout)) {
@>      currentPlatformFee = sentAmount - previousKingPayout;
@>  }
    platformFeesBalance = platformFeesBalance + currentPlatformFee;

    // Remaining amount goes to the pot
    amountToPot = sentAmount - currentPlatformFee;
    pot = pot + amountToPot;
    // ...
}
```

### Risk

**Likelihood**: **High**

* This logical flaw is present in every single call to `claimThrone`.

**Impact**: **Low**

* This issue does not lead to a direct loss or theft of funds. The fee distribution works, but not for the reasons the code suggests.

* The presence of dead, unreachable code makes the contract harder to read, maintain, and audit, and it could mask the true intent of the fee logic.

### Proof of Concept

This issue can be demonstrated by analyzing the variables and the condition itself:

1. **The Condition:** For the `if` block to execute, the condition `currentPlatformFee > (sentAmount - previousKingPayout)` must be true.

2. **Simplifying the Condition:** Since `previousKingPayout` is hardcoded to `0`, the condition simplifies to `currentPlatformFee > sentAmount`.

3. **The Mathematical Impossibility:** We can now substitute the calculation for `currentPlatformFee` into the simplified condition:
   `(sentAmount * platformFeePercentage) / 100 > sentAmount`

   This inequality can never be true. The `platformFeePercentage` is logically capped at 100.

   * If `platformFeePercentage` is 100, the expression becomes `sentAmount > sentAmount`, which is **false**.

   * If `platformFeePercentage` is less than 100, the expression is `(a fraction of sentAmount) > sentAmount`, which is also always **false**.

Since `currentPlatformFee` can at most be equal to `sentAmount` but never greater, the condition is impossible to satisfy, proving the `if` block is unreachable dead code.

### Recommended Mitigation

The easiest way to fix this issue is to implement the previous king payout functionality, as shown in a previous finding.






