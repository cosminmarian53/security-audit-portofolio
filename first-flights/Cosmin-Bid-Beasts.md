# Bid Beasts - Findings Report

# Table of contents
- ## [Contest Summary](#contest-summary)
- ## [Results Summary](#results-summary)
- ## High Risk Findings
    - ### [H-01. [H-1] Anyone Can Burn Any NFT (Unauthorized Destruction of Tokens)](#H-01)
    - ### [H-02. [H-2] Incorrect Authorization in `withdrawAllFailedCredits` Allows Theft of Arbitrary User Funds](#H-02)

- ## Low Risk Findings
    - ### [L-01. [M-1] Incorrect AuctionSettled Event Emitted on New Bid](#L-01)
    - ### [L-02. [L-1]  First Bid Cannot Equal minPrice, Violating Principle of Least Surprise](#L-02)


# <a id='contest-summary'></a>Contest Summary

### Sponsor: First Flight #49

### Dates: Sep 25th, 2025 - Oct 2nd, 2025

[See more contest details here](https://codehawks.cyfrin.io/c/2025-09-bid-beasts)

# <a id='results-summary'></a>Results Summary

### Number of findings:
- High: 2
- Medium: 0
- Low: 2


# High Risk Findings

## <a id='H-01'></a>H-01. [H-1] Anyone Can Burn Any NFT (Unauthorized Destruction of Tokens)            



# \[H-1] Anyone Can Burn Any NFT (Unauthorized Destruction of Tokens)

## Description

Normally, only the owner of an NFT should be able to destroy (burn) their own token, preserving user property rights and preventing malicious griefing.\
In the current implementation, **any address can call** **`burn(uint256 _tokenId)`** **and destroy any NFT, regardless of ownership**. This allows arbitrary users to irreversibly destroy NFTs they do not own.

```Solidity
//@audit -high? anyone can burn anyone else's NFT
function burn(uint256 _tokenId) public {
    _burn(_tokenId); // @> No ownership check here
    emit BidBeastsBurn(msg.sender, _tokenId);
}
```

## Risk

**Likelihood**:

* This will occur whenever any user calls `burn()` with the tokenId of an NFT they do not own.

* There are no access controls or ownership checks in place, so this is trivial to exploit.

**Impact**:

* Any NFT can be destroyed by anyone, resulting in permanent loss of user assets.

* This can be used for griefing, denial of service, or targeted attacks on users or the protocol (e.g., burning NFTs held in escrow by the marketplace).

## Proof of Concept

This issue consists of two cases.
Case 1: Griefing individual users by burning their NFTs
Add the following test to `BidBeastsMarketPlaceTest.t.sol:`

```Solidity
function test_anyone_can_burn_nft() public {
    address randomUser = makeAddr("randomUser");
    vm.deal(randomUser, 1 ether);

    _mintNFT();

    //assert ownership
    assertEq(nft.ownerOf(TOKEN_ID), SELLER);

    //random user burns the nft
    vm.prank(randomUser);
    nft.burn(TOKEN_ID);

    vm.expectRevert();
    nft.ownerOf(TOKEN_ID);
}
```

Case 2: Disrupting protocol invariants by burning NFTs held in escrow, potentially breaking auctions and marketplace logic.

```solidity
function test_anyone_can_burn_nft_while_in_marketplace_escrow() public {
        address randomUser = makeAddr("randomUser");
        vm.deal(randomUser, 1 ether);

        _mintNFT();
        _listNFT();

        //assert ownership
        assertEq(nft.ownerOf(TOKEN_ID), address(market));

        //random user burns the nft
        vm.prank(randomUser);
        nft.burn(TOKEN_ID);

        vm.expectRevert();
        nft.ownerOf(TOKEN_ID);
    }
```

## Recommended Mitigation

Consider adding a check or a modifier to see if the person trying to burn the NFT is the actual owner of the asset.

```diff
- function burn(uint256 _tokenId) public {
-     _burn(_tokenId);
-     emit BidBeastsBurn(msg.sender, _tokenId);
- }
+ function burn(uint256 _tokenId) public {
+     require(ownerOf(_tokenId) == msg.sender, "Not the owner");
+     _burn(_tokenId);
+     emit BidBeastsBurn(msg.sender, _tokenId);
+ }
```

## <a id='H-02'></a>H-02. [H-2] Incorrect Authorization in `withdrawAllFailedCredits` Allows Theft of Arbitrary User Funds            



# Incorrect Authorization in `withdrawAllFailedCredits` Allows Theft of Arbitrary User Funds

## Description

* The contract includes a mechanism to credit users whose ETH transfers fail. The `withdrawAllFailedCredits` function is intended to let users withdraw these credits.

* The function incorrectly uses `_receiver` to determine which balance to withdraw but uses `msg.sender` as the recipient and the address to clear credits for. This allows an attacker (`msg.sender`) to specify a victim (`_receiver`) and drain their failed transfer credits. The victim's credit balance is never cleared, allowing the attacker to repeat the theft.

```Solidity
// src/BidBeastsNFTMarketPlace.sol

function withdrawAllFailedCredits(address _receiver) external {
    uint256 amount = failedTransferCredits[_receiver]; // @> Reads victim's balance
    require(amount > 0, "No credits to withdraw");

    failedTransferCredits[msg.sender] = 0; // @> Clears attacker's balance

    (bool success,) = payable(msg.sender).call{value: amount}(""); // @> Pays attacker
    require(success, "Withdraw failed");
}
```

## Risk

**Likelihood**: **High**

* The function is public and can be called directly by any address.
* An attacker can monitor the contract for `failedTransferCredits` balances to appear and immediately exploit the vulnerability.

**Impact**: **High**

* **Direct theft of funds**: Any funds accrued in the `failedTransferCredits` mapping are directly at risk of being stolen.

## Proof of Concept

Consider the following test case:

```Solidity
// test/BidBeastsMarketPlaceTest.t.sol

function test_PoC_StealFailedCredits() public {
    address maliciousActor = makeAddr("maliciousActor");
    vm.deal(maliciousActor, 1 ether);
    vm.deal(address(rejector), 5 ether);

    _mintNFT();
    _listNFT();

    // A contract that cannot receive ETH places a bid.
    vm.prank(address(rejector));
    market.placeBid{value: MIN_PRICE + 1 ether}(TOKEN_ID);

    // Another user outbids, triggering a refund to the contract, which fails.
    vm.prank(BIDDER_2);
    market.placeBid{value: MIN_PRICE + 2 ether}(TOKEN_ID);
    uint256 expectedCredit = MIN_PRICE + 1 ether;
    assertEq(market.failedTransferCredits(address(rejector)), expectedCredit);

    // The malicious actor calls the function, passing the victim's address.
    uint256 attackerBalanceBefore = maliciousActor.balance;
    vm.prank(maliciousActor);
    market.withdrawAllFailedCredits(address(rejector));

    // The malicious actor successfully steals the funds.
    assertEq(maliciousActor.balance, attackerBalanceBefore + expectedCredit);
    // The victim's balance is not cleared, allowing the attack to be repeated.
    assertEq(market.failedTransferCredits(address(rejector)), expectedCredit);
}
```

## Recommended Mitigation

Consider the following fix:

```diff
// src/BidBeastsNFTMarketPlace.sol
- function withdrawAllFailedCredits(address _receiver) external {
-     uint256 amount = failedTransferCredits[_receiver];
-     require(amount > 0, "No credits to withdraw");
-
-     failedTransferCredits[msg.sender] = 0;
-
-     (bool success,) = payable(msg.sender).call{value: amount}("");
-     require(success, "Withdraw failed");
- }
+ function withdrawFailedCredits() external {
+     uint256 amount = failedTransferCredits[msg.sender];
+     require(amount > 0, "No credits to withdraw");
+
+     failedTransferCredits[msg.sender] = 0;
+
+     (bool success,) = payable(msg.sender).call{value: amount}("");
+     require(success, "Withdraw failed");
+ }
```

    


# Low Risk Findings

## <a id='L-01'></a>L-01. [M-1] Incorrect AuctionSettled Event Emitted on New Bid            



# Incorrect `AuctionSettled` Event Emitted on New Bid, leads to displaying wrong data to off-chain services

## Description

* The contract should emit events that accurately reflect the actions being taken. `BidPlaced` should be emitted for new bids, and `AuctionSettled` for the final sale.

* The `placeBid` function incorrectly emits an `AuctionSettled` event when a new regular bid is made. This provides misleading data to off-chain services and UIs, suggesting an auction has concluded when it is still active.

```Solidity
// src/BidBeastsNFTMarketPlace.sol

        require(msg.sender != previousBidder, "Already highest bidder");
// @> Incorrect event is emitted here, should be `BidPlaced`.
        emit AuctionSettled(tokenId, msg.sender, listing.seller, msg.value);

        // --- Regular Bidding Logic ---
```

## Risk

**Likelihood**: **High**

* This incorrect event is emitted for every non-buy-now bid placed on any auction.

**Impact**: **Low**

* Funds are not at risk.

* The state of the contract is handled incorrectly from an events perspective, disrupting off-chain monitoring and potentially confusing users.

## Proof of Concept

The following test should prove that, the event is emitted wrongfully. Add it to `BidBeastsMarketPlaceTest.t.sol`:

```Solidity
 function test_event_emitted_on_regular_bid() public {
        // Setup: Mint and list NFT
        _mintNFT();
        _listNFT();

        // Place a regular bid (not buy-now)
        vm.prank(BIDDER_1);
        vm.recordLogs();
        market.placeBid{value: MIN_PRICE + 1}(TOKEN_ID);

        Vm.Log[] memory entries = vm.getRecordedLogs();
        bool foundAuctionSettled = false;
        bool foundBidPlaced = false;

        bytes32 auctionSettledSig = keccak256("AuctionSettled(uint256,address,address,uint256)");
        bytes32 bidPlacedSig = keccak256("BidPlaced(uint256,address,uint256)");

        for (uint256 i = 0; i < entries.length; i++) {
            if (entries[i].topics.length > 0) {
                if (entries[i].topics[0] == auctionSettledSig) {
                    foundAuctionSettled = true;
                }
                if (entries[i].topics[0] == bidPlacedSig) {
                    foundBidPlaced = true;
                }
            }
        }

        assertTrue(foundAuctionSettled, "AuctionSettled event should NOT be emitted for a regular bid");
        assertTrue(foundBidPlaced, "BidPlaced event should be emitted for a regular bid");
    }
```

## Recommended Mitigation

Remove the event emission from `placeBid` and move it to `settleAuction` where it should be:

```diff
// src/BidBeastsNFTMarketPlace.sol
        require(msg.sender != previousBidder, "Already highest bidder");
-       emit AuctionSettled(tokenId, msg.sender, listing.seller, msg.value);

        // --- Regular Bidding Logic ---
        ....
}
...
function settleAuction(uint256 tokenId) external isListed(tokenId) {
//settle auction logic here
        ...

        _executeSale(tokenId);
        // this is where the event should be emitted
+       emit AuctionSettled(tokenId, msg.sender, listing.seller, msg.value);
```

## <a id='L-02'></a>L-02. [L-1]  First Bid Cannot Equal minPrice, Violating Principle of Least Surprise            



# First Bid Cannot Equal minPrice, Violating Principle of Least Surprise

## Description

* An auction's `minPrice` should represent the lowest acceptable bid. A user should be able to place a bid equal to this price.

* The check for the first bid requires that `msg.value` be strictly greater than (`>`) the `minPrice`. This prevents users from placing a bid exactly equal to the minimum price, which is counter-intuitive and undocumented behavior.

```Solidity
// src/BidBeastsNFTMarketPlace.sol

if (previousBidAmount == 0) {
    requiredAmount = listing.minPrice;
// @> Use of `>` prevents bidding the exact minPrice
    require(msg.value > requiredAmount, "First bid must be > min price");
    listing.auctionEnd = block.timestamp + S_AUCTION_EXTENSION_DURATION;
```

## Risk

**Likelihood**: **Medium**

* This will occur whenever a user attempts to open bidding at the exact minimum price.

**Impact**: **Low**

* Funds are not at risk.
* A function is incorrect, causing user transactions to revert unexpectedly and creating a slight disruption in protocol functionality.

## Proof of Concept

Both `test_placeSubsequentBid_RefundsPrevious`and `test_placeFirstBid` revert because the user places a bid with the minimum amount.  

```Solidity
function test_placeFirstBid() public {
        _mintNFT();
        _listNFT();

        vm.prank(BIDDER_1);
       >@ market.placeBid{value: MIN_PRICE}(TOKEN_ID); //placing with with MIN_VALUE will revert

        BidBeastsNFTMarket.Bid memory highestBid = market.getHighestBid(TOKEN_ID);
        assertEq(highestBid.bidder, BIDDER_1);
        assertEq(highestBid.amount, MIN_PRICE);
        assertEq(market.getListing(TOKEN_ID).auctionEnd, block.timestamp + market.S_AUCTION_EXTENSION_DURATION());
    }

    function test_placeSubsequentBid_RefundsPrevious() public {
        _mintNFT();
        _listNFT();

        vm.prank(BIDDER_1);
        >@ market.placeBid{value: MIN_PRICE}(TOKEN_ID); //placing with with MIN_VALUE will revert( same as before)

        uint256 bidder1BalanceBefore = BIDDER_1.balance;

        uint256 secondBidAmount = MIN_PRICE * 120 / 100; // 20% increase
        vm.prank(BIDDER_2);
        market.placeBid{value: secondBidAmount}(TOKEN_ID);

        // Check if bidder 1 was refunded
        assertEq(BIDDER_1.balance, bidder1BalanceBefore + MIN_PRICE, "Bidder 1 was not refunded");

        BidBeastsNFTMarket.Bid memory highestBid = market.getHighestBid(TOKEN_ID);
        assertEq(highestBid.bidder, BIDDER_2, "Bidder 2 should be the new highest bidder");
        assertEq(highestBid.amount, secondBidAmount, "New highest bid amount is incorrect");
    }
```

## Recommended Mitigation

Consider using >=: 

```diff
// src/BidBeastsNFTMarketPlace.sol
-   require(msg.value > requiredAmount, "First bid must be > min price");
+   require(msg.value >= requiredAmount, "First bid must be >= min price");
```



