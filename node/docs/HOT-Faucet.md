# HOT Faucet Instructions
## How do I fund my SubstratumNode for testing with testnet Ether?

##### 1 ROP = 5000 HOT

### Request Testnet Ether (ROP)

1. Submit a request for Ropsten Ethereum from https://faucet.ropsten.be/
    1. Paste your SubstratumNode consuming wallet testnet address -- This is the address you noted when recording your mnemonic phrase words when generating
      your wallet. If you didn't record it you can scan SubstratumNode_rCURRENT.log in the temporary directory.
      
    1. Click the "Send me test Ether" button -- Note you are rate limited as to how frequently you can request test Ether.

1. HOT is the testnet version of $SUB we use in lieu of the real thing. In production it will be real $SUB.
    1. To obtain HOT in a self-service fashion we have created a HOTSwap Faucet for tokens. To "buy" HOT you send ROP to the HOTSwap contract by invoking the `buyTokens()` smart contract function.
    1. Since `buyTokens()` is not a standard ERC20 function, web forms like those for `transfer()` and other standard functions are unavailable for our custom function. With a few extra steps we can still invoke the function. 
    1. We have documented 2 methods to use `buyTokens()` to fund your consuming wallet address with HOT.
        1. Method 1 using MEW
        1. Method 2 using Etherscan with Metamask
   

### Method 1: Using MyEtherWallet.com to invoke `buyTokens()`

1. In your browser go to https://vintage.myetherwallet.com/ (It's best to copy and paste the link and not trust anyone to give you a link to click). 
    * Note that as of this writing the newest version of MEW does not yet support providing a gas limit and fails to properly invoke the `buyTokens()` function.
1. Select 1 Gwei as the gas price.
1. Click on the Contracts tab.
1. Copy the HOTSwap contract address from here --> 0x1D735051A431c06185927C27AEcea99520634832 and paste it in the "Contract Address" field.

    ![Image 1](images/HOTFaucet-01.png "Image 1")

1. Also copy the `buyTokens()` JSON Interface text: 
````json
[{"constant": false, "inputs": [{"name": "beneficiary", "type": "address"}], "name": "buyTokens", "outputs": [], "payable": true, "stateMutability": "payable", "type": "function"}]
````
 
and paste it in the "ABI / JSON Interface" field. 
1. Click the __Access__ button
1. When presented with the "Select a function" drop-down, select `buyTokens`. See the image below 

    ![Image 2](images/HOTFaucet-02.png "Image 2")

1. Selecting `buyTokens` will expand the form to reveal a "beneficiary" address field. Enter the consuming wallet address from which you will send test Ether (ROP). This the same address you used in step 1 of **Request Testnet Ether (ROP)** above.

    ![Image 3](images/HOTFaucet-03.png "Image 3")

1. Use the MEW Wallet Access form to access your testnet consuming wallet address. Find the address where you requested the testnet Ether (ROP) to be sent. Note you may have to choose the correct "Select HD derivation path" radio button as Ropsten may default to `m/44'/1'/0'/0`. We recommend using the mainnet path `m/44'/60'/0'/0` even though we're using Ropsten for testing. SubstratumNode will default to a mainnet path. All Ethereum addresses are compatible with mainnet and testnets.
1. Click the Write button.

    ![Image 4](images/HOTFaucet-04.png "Image 4")
    
    1. You will be presented with a dialog requesting the amount of ROPSTEN ETH you wish to send. Enter an amount. Note you will have to allow for gas fees to be taken so it may be less than 1 Ropsten ETH.
    1. Enter a gas limit (if 60,000 is insufficient you will need to use more)
    1. Click "Generate Transaction"
    1. Review the "Raw Transaction" and "Signed Transaction" fields. See the image below.
     
    ![Image 5](images/HOTFaucet-05.png "Image 4")

    1. Click "Yes, I am sure! Make Transaction." when ready.
    1. You may click the links MEW provides in the footer to monitor transaction status. Note they may only display for a brief amount of time.
    
    ![Image 6](images/HOTFaucet-06.png "Image 6")
    
    1. If an error occurs you may see a result like the image below. 
    
    ![Image 8](images/HOTFaucet-08.png "Image 8")
    
    This particular example the HOTSwap Faucet was initially given a limited quantity of tokens to sell. You may more likely encounter a failure if you use a gas limit that is too low. The error in that case will likely be "Out of gas." Try to send the transaction again but with a higher gas limit (also confirm you selected 1 Gwei as the gas price above).
    
    1. If the transaction processes normally you should see a result like the following image.
    
    ![Image 7](images/HOTFaucet-07.png "Image 7") 


### Method 2: Using etherscan.io to invoke `buyTokens()` via Metamask

#### Pre-requisites: 
1. You must have generated a 12-word mnemonic recovery phrase with SubstratumNode to be able to use Metamask. You can still do so if you didn't the first time. It may mean you need to move some testnet Ether (ROP) to an address unlocked by the 12-word mnemonic if you already requested Ether from a faucet following earlier instructions. 
1. You must install the MetaMask browser extension. See https://metamask.io/.
1. You may need to restart your browser if you don't see the "Connect with Metamask" link on the **Write Contract** tab.

#### Instructions
1. Open https://ropsten.etherscan.io/address/0x1d735051a431c06185927c27aecea99520634832
1. Or search for the HOTSwap Contract by address --> 0x1D735051A431c06185927C27AEcea99520634832 on https://ropsten.etherscan.io/ 
1. Select the "Write Contract" tab. ![Image 9](images/HOTFaucet-09.png "Image 9")
1. Click the " Connect with Metamask" link and observe the link disappears and the icon becomes green.

    ![Image 10](images/HOTFaucet-10.png "Image 10")

1. Scroll to find 3. buyToken section fields
    ![Image 11](images/HOTFaucet-11.png "Image 11")

1. Enter amount of testnet Ether (ROP) you are spending to buy tokens (1 ROP = 5,000 HOT, 0.9 ROP = 4,500 HOT etc.)
    * NOTE: remember to allow for gas fees to be taken from your spending amount   
    ![Image 12](images/HOTFaucet-12.png "Image 12")
    
1. Enter your consuming wallet address in the "beneficiary (address)" field.
    ![Image 13](images/HOTFaucet-13.png "Image 13")

1. Click the "write" button and a "Metamask Notification" dialog should display.
    * You may Use the edit link to adjust the gas fee to set the gas price to 1 Gwei and gas limit to 100,000 or more if necessary
    * Click the "Confirm" button to complete your transaction.  
    
    ![Image 14](images/HOTFaucet-14.png "Image 14")

1. Click the "View your transaction" button to see the results 

![Image 15](images/HOTFaucet-15.png "Image 15")

1. Your transaction should look similar to the following:

![Image 16](images/HOTFaucet-16.png "Image 16")
