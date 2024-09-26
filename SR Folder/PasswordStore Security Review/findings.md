### [H-1] Storing the password on-chain makes it visible to anyone and no longer private

**Description:** All data stored on chain is public and visible to anyone. The `PasswordStore::s_password` variable is intended to be hidden and only accessible by the owner through the `PasswordStore::getPassword` function.

I show one such method of reading any data off chain below.

**Impact:** Anyone is able to read the private password, severly breaking the functionality of the protocol.

**Proof of Concept:**

1. Create a locally running chain 
``` zsh
make anvil
```

2. Deploy the contract to the chain 
```
make deploy
```

3. Run the storage tool 
```
cast storage <CONTRACT ADDRESS> 1 --rpc-url http://localhost:8545 

```
You'll get an output that looks like this:
`0x6d7950617373776f726400000000000000000000000000000000000000000014`

You can then parse that hex to a string with:
```
cast --parse-bytes32-string 0x6d7950617373776f726400000000000000000000000000000000000000000014
```

And then get an output of:
```
myPassword
```


### [H-2] `PasswordStore::setPassword` has no access controls, meaning a non-owner could change the password

**Description:** The `PasswordStore::setPassword` function is set to be an `external` function, however the purpose of the smart contract and function's natspec indicate that `This function allows only the owner to set a new password.`

``` solidity
function setPassword(string memory newPassword) external {
->  // @Audit - There are no Access Controls.
    s_password = newPassword;
    emit SetNewPassword();
}
```

**Impact:** Anyone can set/change the stored password, severly breaking the contract's intended functionality

**Proof of Concept:** Add the following to the PasswordStore.t.sol test file:

``` solidity 
    function test_access_control_of_set_password(address randomAddress) public {        
            
        vm.prank(randomAddress);
        string memory newPassword = "newPassword";
        passwordStore.setPassword(newPassword);

        vm.prank(owner);
        string memory actualPassword = passwordStore.getPassword();

        assertEq(actualPassword, newPassword);
    }
```


**Recommended Mitigation:** Add an access control conditional to `PasswordStore::setPassword`.

``` solidity 
if(msg.sender != s_owner){
    revert PasswordStore__NotOwner();
}
```

### [I-1] The `PasswordStore::getPassword` natspec indicates a parameter that doesn't exist, causing the natspec to be incorrect.

**Description:**
```
/*
* @notice This allows only the owner to retrieve the password.
-> * @param newPassword The new password to set.
*/
function getPassword() external view returns (string memory) {}
```

The `PasswordStore::getPassword` function signature is `getPassword()` while the natspec says it should be `getPassword(string)`.

**Impact:** The natspec is incorrect

**Recommended Mitigation:** Remove the incorrect natspec line.

``` diff
/*
* @notice This allows only the owner to retrieve the password.
-> * @param newPassword The new password to set.
*/
```
