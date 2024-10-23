



## [L-1] `TokenFactory::deployToken` can create multiple token with same symbol

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
    }
```
