// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/AllowanceModule.sol";
import "safe-contracts/contracts/SafeL2.sol";
import "safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import "safe-contracts/contracts/proxies/SafeProxy.sol";
import "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";

contract ERC20Token is ERC20 {
    constructor(uint256 initialSupply) ERC20("TEST", "TEST") {
        _mint(msg.sender, initialSupply);
    }
}

contract AllowanceTest is Test {
    address hotWallet;
    address coldWallet;
    address secretWallet;
    address tokenRecipient;
    address tokenHacker;

    uint256 hotWalletPk;
    uint256 coldWalletPk;
    uint256 secretWalletPk;
    uint256 tokenHackerPk;

    address[] public owners = new address[](3);
    uint256 public threshold = 2;
    uint256 public tokenInitialSupply = 1e24; // 1000000 ERC20 Token (excluding the Decimals with 18 precision).

    AllowanceModule public allowanceModule;
    address public singleton;
    SafeL2 public safe;
    SafeProxyFactory public safeProxyFactory;
    ERC20 public erc20;
    uint256 salt; // Note: This is not suitable for production, just for testing.

    event allowanceExecuted(
        address _initiator, address indexed _safe, address indexed _token, address indexed _beneficiary, uint256 _amount
    );

    function setUp() public {
        // Creating wallets for testing purposes. (Address in ascending order).
        (secretWallet, secretWalletPk) = makeAddrAndKey("SecretWallet");
        (hotWallet, hotWalletPk) = makeAddrAndKey("HotWallet");
        (coldWallet, coldWalletPk) = makeAddrAndKey("ColdWallet");

        // Setting owners.
        owners = [hotWallet, coldWallet, secretWallet];

        vm.startPrank(coldWallet);

        // Setting up safe wallet.
        singleton = address(new SafeL2());
        safeProxyFactory = new SafeProxyFactory();
        bytes memory setupData = abi.encodeWithSelector(
            Safe.setup.selector, owners, threshold, address(0), "0x", address(0), address(0), 0, payable(address(0))
        );

        salt++;
        safe = SafeL2(payable(safeProxyFactory.createProxyWithNonce(singleton, setupData, salt)));

        // Creating ERC20 Token for testing.
        erc20 = new ERC20Token(tokenInitialSupply);

        // Creating Module for Testing.
        allowanceModule = new AllowanceModule(address(safe), address(erc20));

        // Creating Tx Data and Hash to enable module.
        uint256 _safeNonce = safe.nonce();
        bytes memory enableModuleData = abi.encodeWithSignature("enableModule(address)", address(allowanceModule));
        bytes32 enableModuleTxHash = safe.getTransactionHash(
            address(safe), 0, enableModuleData, Enum.Operation.Call, 0, 0, 0, address(0), address(0), _safeNonce
        );
        vm.stopPrank();

        // Creating signed content for safe wallet.
        bytes memory sig;

        {
            (uint8 v0, bytes32 r0, bytes32 s0) = vm.sign(hotWalletPk, enableModuleTxHash);
            (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(coldWalletPk, enableModuleTxHash);
            sig = abi.encodePacked(r0, s0, v0, r1, s1, v1);
        }

        // Tx to enable module.
        bool status = safe.execTransaction(
            address(safe), 0, enableModuleData, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), sig
        );

        assertTrue(status);

        // Creating wallets for other testing.
        tokenRecipient = makeAddr("Token Recipient");
        (tokenHacker, tokenHackerPk) = makeAddrAndKey("Token Hacker");
    }

    // Normal Workflow in an ideal situation.
    function testNormalWorkflow() public {
        // Amount to be made transferred to Wallet and to make transferrable.
        uint256 amount = 100e18;
        uint256 amountTransferrable = 75e18;

        // Get the token balance of Safe Wallet before transfer.
        uint256 swBalBeforeTransfer = erc20.balanceOf(address(safe));

        vm.startPrank(coldWallet);

        // Transferring token to Safe Wallet.
        erc20.transfer(address(safe), amount);

        // Get the token balance of Safe Wallet after transfer.
        uint256 swBalAfterTransfer = erc20.balanceOf(address(safe));

        // Check the token balance of Safe Wallet is correct.
        assertEq(amount + swBalBeforeTransfer, swBalAfterTransfer);

        vm.stopPrank();

        // Get the current timestamp for expiry calculation and nonce of Module.
        uint256 expiry = block.timestamp + 100;
        uint256 moduleNonce = allowanceModule.sigNonce();

        (bytes32 moduleTransferHash,) =
            allowanceModule.generateTransferDataAndHash(tokenRecipient, amountTransferrable, expiry, moduleNonce);

        bytes memory sig;

        {
            // Signing for Token Transfer by Secret Wallet.
            (uint8 v0, bytes32 r0, bytes32 s0) = vm.sign(secretWalletPk, moduleTransferHash);

            // Signing for Token Transfer by Hot Wallet.
            (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(hotWalletPk, moduleTransferHash);
            sig = abi.encodePacked(r0, s0, v0, r1, s1, v1);
        }

        // Get the token balance of Token Recipient before transfer by Module.
        uint256 trBalBeforeTransfer = erc20.balanceOf(tokenRecipient);

        // Initiate the transaction from Module.
        allowanceModule.executeAllowance(tokenRecipient, amountTransferrable, sig, expiry);

        // Get the token balance of Token Recipient after transfer by Module.
        uint256 trBalAfterTransfer = erc20.balanceOf(tokenRecipient);

        // Check the token balance of Token Recipient is correct.
        assertEq(trBalBeforeTransfer + amountTransferrable, trBalAfterTransfer);

        // Get the token balance of Safe Wallet after transfer by Module.
        uint256 swBalAfterModuleTransfer = erc20.balanceOf(address(safe));

        // Check the token balance of Safe Wallet is correct.
        assertEq(swBalAfterTransfer, swBalAfterModuleTransfer + amountTransferrable);
    }

    // Trying to use the signature without any balance in safe wallet should fail.
    function testFailWithoutSafeWalletBalance() public {
        // Amount to be made transferrable. But no amount actually transferred to Safe Wallet.
        uint256 amountTransferrable = 75e18;

        // Get the current timestamp for expiry calculation and nonce of Module.
        uint256 expiry = block.timestamp + 100;
        uint256 moduleNonce = allowanceModule.sigNonce();

        (bytes32 moduleTransferHash,) =
            allowanceModule.generateTransferDataAndHash(tokenRecipient, amountTransferrable, expiry, moduleNonce);

        bytes memory sig;

        {
            // Signing for Token Transfer by Secret Wallet.
            (uint8 v0, bytes32 r0, bytes32 s0) = vm.sign(secretWalletPk, moduleTransferHash);

            // Signing for Token Transfer by Hot Wallet.
            (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(hotWalletPk, moduleTransferHash);
            sig = abi.encodePacked(r0, s0, v0, r1, s1, v1);
        }

        // Initiate the transaction from Module.
        allowanceModule.executeAllowance(tokenRecipient, amountTransferrable, sig, expiry);
    }

    // Trying to use only one signature for a safe wallet with threashold of two should fail.
    function testFailWithoutCompleteSignature() public {
        // Amount to be made transferred to Wallet and to make transferrable.
        uint256 amount = 100e18;
        uint256 amountTransferrable = 75e18;

        // Get the token balance of Safe Wallet before transfer.
        uint256 swBalBeforeTransfer = erc20.balanceOf(address(safe));

        vm.startPrank(coldWallet);

        // Transferring token to Safe Wallet.
        erc20.transfer(address(safe), amount);

        // Get the token balance of Safe Wallet after transfer.
        uint256 swBalAfterTransfer = erc20.balanceOf(address(safe));

        // Check the token balance of Safe Wallet is correct.
        assertEq(amount + swBalBeforeTransfer, swBalAfterTransfer);

        vm.stopPrank();

        // Get the current timestamp for expiry calculation and nonce of Module.
        uint256 expiry = block.timestamp + 100;
        uint256 moduleNonce = allowanceModule.sigNonce();

        (bytes32 moduleTransferHash,) =
            allowanceModule.generateTransferDataAndHash(tokenRecipient, amountTransferrable, expiry, moduleNonce);

        bytes memory sig;

        {
            // Signing for Token Transfer by Secret Wallet.
            (uint8 v0, bytes32 r0, bytes32 s0) = vm.sign(secretWalletPk, moduleTransferHash);

            // Only one signature being used for a Safe Wallet with threshold of two.
            sig = abi.encodePacked(r0, s0, v0);
        }

        // Initiate the transaction from Module.
        allowanceModule.executeAllowance(tokenRecipient, amountTransferrable, sig, expiry);
    }

    // Trying to use wrong signature for a safe wallet should fail.
    function testFailWithWrongSignature() public {
        // Amount to be made transferred to Wallet and to make transferrable.
        uint256 amount = 100e18;
        uint256 amountTransferrable = 75e18;

        // Get the token balance of Safe Wallet before transfer.
        uint256 swBalBeforeTransfer = erc20.balanceOf(address(safe));

        vm.startPrank(coldWallet);

        // Transferring token to Safe Wallet.
        erc20.transfer(address(safe), amount);

        // Get the token balance of Safe Wallet after transfer.
        uint256 swBalAfterTransfer = erc20.balanceOf(address(safe));

        // Check the token balance of Safe Wallet is correct.
        assertEq(amount + swBalBeforeTransfer, swBalAfterTransfer);

        vm.stopPrank();

        // Get the current timestamp for expiry calculation and nonce of Module.
        uint256 expiry = block.timestamp + 100;
        uint256 moduleNonce = allowanceModule.sigNonce();

        (bytes32 moduleTransferHash,) =
            allowanceModule.generateTransferDataAndHash(tokenRecipient, amountTransferrable, expiry, moduleNonce);

        bytes memory sig;

        {
            // Signing for Token Transfer by Token Hacker.
            (uint8 v0, bytes32 r0, bytes32 s0) = vm.sign(tokenHackerPk, moduleTransferHash);

            // Signing for Token Transfer by Hot Wallet. Somehow Token Hacker hacked the Hot wallet.
            (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(hotWalletPk, moduleTransferHash);
            sig = abi.encodePacked(r0, s0, v0, r1, s1, v1);
        }

        // Initiate the transaction from Module.
        allowanceModule.executeAllowance(tokenRecipient, amountTransferrable, sig, expiry);
    }

    // Trying to use the right signature but with wrong token should fail.
    function testFailWithWrongToken() public {
        vm.startPrank(coldWallet);

        // Creating new ERC20 Token for testing.
        ERC20 newErc20 = new ERC20Token(tokenInitialSupply);

        // Amount to be made transferred to Wallet and to make transferrable.
        uint256 amount = 100e18;
        uint256 amountTransferrable = 75e18;

        // Get the token balance of Safe Wallet before transfer.
        uint256 swBalBeforeTransfer = newErc20.balanceOf(address(safe));

        // Transferring token to Safe Wallet.
        newErc20.transfer(address(safe), amount);

        // Get the token balance of Safe Wallet after transfer.
        uint256 swBalAfterTransfer = newErc20.balanceOf(address(safe));

        // Check the token balance of Safe Wallet is correct.
        assertEq(amount + swBalBeforeTransfer, swBalAfterTransfer);

        vm.stopPrank();

        // Get the current timestamp for expiry calculation and nonce of Module.
        uint256 expiry = block.timestamp + 100;
        uint256 moduleNonce = allowanceModule.sigNonce();

        // Module Transfer Hash created with new token address.
        uint256 chainId = allowanceModule.getChainId();
        bytes32 domainSeparator =
            keccak256(abi.encode(allowanceModule.DOMAIN_SEPARATOR_TYPEHASH(), chainId, address(safe)));
        bytes32 transferHash = keccak256(
            abi.encode(
                allowanceModule.ALLOWANCE_MODULE_TYPEHASH(),
                address(safe),
                address(newErc20),
                tokenRecipient,
                amountTransferrable,
                expiry,
                moduleNonce
            )
        );
        bytes32 moduleTransferHash =
            keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator, transferHash));

        bytes memory sig;

        {
            // Signing for Token Transfer by Secret Wallet.
            (uint8 v0, bytes32 r0, bytes32 s0) = vm.sign(secretWalletPk, moduleTransferHash);

            // Signing for Token Transfer by Hot Wallet.
            (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(hotWalletPk, moduleTransferHash);
            sig = abi.encodePacked(r0, s0, v0, r1, s1, v1);
        }

        // Initiate the transaction from Module.
        allowanceModule.executeAllowance(tokenRecipient, amountTransferrable, sig, expiry);
    }

    // Trying to use the right signature but with wrong safe wallet should fail.
    function testFailWithWrongSafe() public {
        vm.startPrank(coldWallet);

        // Setting up a new safe wallet.
        bytes memory setupData = abi.encodeWithSelector(
            Safe.setup.selector, owners, threshold, address(0), "0x", address(0), address(0), 0, payable(address(0))
        );

        salt++;
        SafeL2 newSafe = SafeL2(payable(safeProxyFactory.createProxyWithNonce(singleton, setupData, salt)));

        // Amount to be made transferred to Wallet and to make transferrable.
        uint256 amount = 100e18;
        uint256 amountTransferrable = 75e18;

        // Get the token balance of Safe Wallet before transfer.
        uint256 swBalBeforeTransfer = erc20.balanceOf(address(newSafe));

        // Transferring token to Safe Wallet.
        erc20.transfer(address(newSafe), amount);

        // Get the token balance of Safe Wallet after transfer.
        uint256 swBalAfterTransfer = erc20.balanceOf(address(newSafe));

        // Check the token balance of Safe Wallet is correct.
        assertEq(amount + swBalBeforeTransfer, swBalAfterTransfer);

        vm.stopPrank();

        // Get the current timestamp for expiry calculation and nonce of Module.
        uint256 expiry = block.timestamp + 100;
        uint256 moduleNonce = allowanceModule.sigNonce();

        // Module Transfer Hash created with new Safe address.
        uint256 chainId = allowanceModule.getChainId();
        bytes32 domainSeparator =
            keccak256(abi.encode(allowanceModule.DOMAIN_SEPARATOR_TYPEHASH(), chainId, address(newSafe)));
        bytes32 transferHash = keccak256(
            abi.encode(
                allowanceModule.ALLOWANCE_MODULE_TYPEHASH(),
                address(newSafe),
                address(erc20),
                tokenRecipient,
                amountTransferrable,
                expiry,
                moduleNonce
            )
        );
        bytes32 moduleTransferHash =
            keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator, transferHash));

        bytes memory sig;

        {
            // Signing for Token Transfer by Secret Wallet.
            (uint8 v0, bytes32 r0, bytes32 s0) = vm.sign(secretWalletPk, moduleTransferHash);

            // Signing for Token Transfer by Hot Wallet.
            (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(hotWalletPk, moduleTransferHash);
            sig = abi.encodePacked(r0, s0, v0, r1, s1, v1);
        }

        // Initiate the transaction from Module.
        allowanceModule.executeAllowance(tokenRecipient, amountTransferrable, sig, expiry);
    }

    // Trying to reuse the correct signature twice should fail even if there is enough balance in wallet.
    function testFailReuseSignature() public {
        // Amount to be made transferred to Wallet and to make transferrable.
        uint256 amount = 200e18;
        uint256 amountTransferrable = 75e18;

        // Get the token balance of Safe Wallet before transfer.
        uint256 swBalBeforeTransfer = erc20.balanceOf(address(safe));

        vm.startPrank(coldWallet);

        // Transferring token to Safe Wallet.
        erc20.transfer(address(safe), amount);

        // Get the token balance of Safe Wallet after transfer.
        uint256 swBalAfterTransfer = erc20.balanceOf(address(safe));

        // Check the token balance of Safe Wallet is correct.
        assertEq(amount + swBalBeforeTransfer, swBalAfterTransfer);

        vm.stopPrank();

        // Get the current timestamp for expiry calculation and nonce of Module.
        uint256 expiry = block.timestamp + 100;
        uint256 moduleNonce = allowanceModule.sigNonce();

        (bytes32 moduleTransferHash,) =
            allowanceModule.generateTransferDataAndHash(tokenRecipient, amountTransferrable, expiry, moduleNonce);

        bytes memory sig;

        {
            // Signing for Token Transfer by Secret Wallet.
            (uint8 v0, bytes32 r0, bytes32 s0) = vm.sign(secretWalletPk, moduleTransferHash);

            // Signing for Token Transfer by Hot Wallet.
            (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(hotWalletPk, moduleTransferHash);
            sig = abi.encodePacked(r0, s0, v0, r1, s1, v1);
        }

        // Get the token balance of Token Recipient before transfer by Module.
        uint256 trBalBeforeTransfer = erc20.balanceOf(tokenRecipient);

        // Initiate the transaction from Module.
        allowanceModule.executeAllowance(tokenRecipient, amountTransferrable, sig, expiry);

        // Get the token balance of Token Recipient after transfer by Module.
        uint256 trBalAfterTransfer = erc20.balanceOf(tokenRecipient);

        // Check the token balance of Token Recipient is correct.
        assertEq(trBalBeforeTransfer + amountTransferrable, trBalAfterTransfer);

        // Get the token balance of Safe Wallet after transfer by Module.
        uint256 swBalAfterModuleTransfer = erc20.balanceOf(address(safe));

        // Check the token balance of Safe Wallet is correct.
        assertEq(swBalAfterTransfer, swBalAfterModuleTransfer + amountTransferrable);

        // Initiate the transaction from Module again with the same signature.
        allowanceModule.executeAllowance(tokenRecipient, amountTransferrable, sig, expiry);
    }

    // Trying to send to the wrong beneficiary should fail.
    function testFailWrongBeneficiary() public {
        // Amount to be made transferred to Wallet and to make transferrable.
        uint256 amount = 100e18;
        uint256 amountTransferrable = 75e18;

        // Get the token balance of Safe Wallet before transfer.
        uint256 swBalBeforeTransfer = erc20.balanceOf(address(safe));

        vm.startPrank(coldWallet);

        // Transferring token to Safe Wallet.
        erc20.transfer(address(safe), amount);

        // Get the token balance of Safe Wallet after transfer.
        uint256 swBalAfterTransfer = erc20.balanceOf(address(safe));

        // Check the token balance of Safe Wallet is correct.
        assertEq(amount + swBalBeforeTransfer, swBalAfterTransfer);

        vm.stopPrank();

        // Get the current timestamp for expiry calculation and nonce of Module.
        uint256 expiry = block.timestamp + 100;
        uint256 moduleNonce = allowanceModule.sigNonce();

        (bytes32 moduleTransferHash,) =
            allowanceModule.generateTransferDataAndHash(tokenRecipient, amountTransferrable, expiry, moduleNonce);

        bytes memory sig;

        {
            // Signing for Token Transfer by Secret Wallet.
            (uint8 v0, bytes32 r0, bytes32 s0) = vm.sign(secretWalletPk, moduleTransferHash);

            // Signing for Token Transfer by Hot Wallet.
            (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(hotWalletPk, moduleTransferHash);
            sig = abi.encodePacked(r0, s0, v0, r1, s1, v1);
        }

        // Initiate the transaction from Module with wrong beneficiary address.
        allowanceModule.executeAllowance(tokenHacker, amountTransferrable, sig, expiry);
    }

    // Trying to send the wrong amount (higher amount) should fail.
    function testFailHigherAmount() public {
        // Amount to be made transferred to Wallet and to make transferrable.
        uint256 amount = 100e18;
        uint256 amountTransferrable = 75e18;

        // Get the token balance of Safe Wallet before transfer.
        uint256 swBalBeforeTransfer = erc20.balanceOf(address(safe));

        vm.startPrank(coldWallet);

        // Transferring token to Safe Wallet.
        erc20.transfer(address(safe), amount);

        // Get the token balance of Safe Wallet after transfer.
        uint256 swBalAfterTransfer = erc20.balanceOf(address(safe));

        // Check the token balance of Safe Wallet is correct.
        assertEq(amount + swBalBeforeTransfer, swBalAfterTransfer);

        vm.stopPrank();

        // Get the current timestamp for expiry calculation and nonce of Module.
        uint256 expiry = block.timestamp + 100;
        uint256 moduleNonce = allowanceModule.sigNonce();

        (bytes32 moduleTransferHash,) =
            allowanceModule.generateTransferDataAndHash(tokenRecipient, amountTransferrable, expiry, moduleNonce);

        bytes memory sig;

        {
            // Signing for Token Transfer by Secret Wallet.
            (uint8 v0, bytes32 r0, bytes32 s0) = vm.sign(secretWalletPk, moduleTransferHash);

            // Signing for Token Transfer by Hot Wallet.
            (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(hotWalletPk, moduleTransferHash);
            sig = abi.encodePacked(r0, s0, v0, r1, s1, v1);
        }

        // Initiate the transaction from Module.
        allowanceModule.executeAllowance(tokenRecipient, amount, sig, expiry);
    }

    // Trying to send amount as zero should fail.
    function testFailZeroAmount() public {
        // Amount to be made transferred to Wallet and to make transferrable.
        uint256 amount = 100e18;
        uint256 amountTransferrable = 75e18;

        // Get the token balance of Safe Wallet before transfer.
        uint256 swBalBeforeTransfer = erc20.balanceOf(address(safe));

        vm.startPrank(coldWallet);

        // Transferring token to Safe Wallet.
        erc20.transfer(address(safe), amount);

        // Get the token balance of Safe Wallet after transfer.
        uint256 swBalAfterTransfer = erc20.balanceOf(address(safe));

        // Check the token balance of Safe Wallet is correct.
        assertEq(amount + swBalBeforeTransfer, swBalAfterTransfer);

        vm.stopPrank();

        // Get the current timestamp for expiry calculation and nonce of Module.
        uint256 expiry = block.timestamp + 100;
        uint256 moduleNonce = allowanceModule.sigNonce();

        (bytes32 moduleTransferHash,) =
            allowanceModule.generateTransferDataAndHash(tokenRecipient, amountTransferrable, expiry, moduleNonce);

        bytes memory sig;

        {
            // Signing for Token Transfer by Secret Wallet.
            (uint8 v0, bytes32 r0, bytes32 s0) = vm.sign(secretWalletPk, moduleTransferHash);

            // Signing for Token Transfer by Hot Wallet.
            (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(hotWalletPk, moduleTransferHash);
            sig = abi.encodePacked(r0, s0, v0, r1, s1, v1);
        }

        // Initiate the transaction from Module.
        allowanceModule.executeAllowance(tokenRecipient, 0, sig, expiry);
    }

    // Trying to send tokens after expiry of the signature should fail.
    function testFailPastExpiry() public {
        // Amount to be made transferred to Wallet and to make transferrable.
        uint256 amount = 100e18;
        uint256 amountTransferrable = 75e18;

        // Get the token balance of Safe Wallet before transfer.
        uint256 swBalBeforeTransfer = erc20.balanceOf(address(safe));

        vm.startPrank(coldWallet);

        // Transferring token to Safe Wallet.
        erc20.transfer(address(safe), amount);

        // Get the token balance of Safe Wallet after transfer.
        uint256 swBalAfterTransfer = erc20.balanceOf(address(safe));

        // Check the token balance of Safe Wallet is correct.
        assertEq(amount + swBalBeforeTransfer, swBalAfterTransfer);

        vm.stopPrank();

        // Get the current timestamp for expiry and nonce of Module.
        uint256 expiry = block.timestamp;
        uint256 moduleNonce = allowanceModule.sigNonce();

        (bytes32 moduleTransferHash,) =
            allowanceModule.generateTransferDataAndHash(tokenRecipient, amountTransferrable, expiry, moduleNonce);

        bytes memory sig;

        {
            // Signing for Token Transfer by Secret Wallet.
            (uint8 v0, bytes32 r0, bytes32 s0) = vm.sign(secretWalletPk, moduleTransferHash);

            // Signing for Token Transfer by Hot Wallet.
            (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(hotWalletPk, moduleTransferHash);
            sig = abi.encodePacked(r0, s0, v0, r1, s1, v1);
        }

        // Initiate the transaction from Module.
        allowanceModule.executeAllowance(tokenRecipient, amountTransferrable, sig, expiry);
    }

    // Check event emitting on correct transfer.
    function testEventEmissionOnAllowanceExecution() public {
        // Amount to be made transferred to Wallet and to make transferrable.
        uint256 amount = 100e18;
        uint256 amountTransferrable = 75e18;

        // Get the token balance of Safe Wallet before transfer.
        uint256 swBalBeforeTransfer = erc20.balanceOf(address(safe));

        vm.startPrank(coldWallet);

        // Transferring token to Safe Wallet.
        erc20.transfer(address(safe), amount);

        // Get the token balance of Safe Wallet after transfer.
        uint256 swBalAfterTransfer = erc20.balanceOf(address(safe));

        // Check the token balance of Safe Wallet is correct.
        assertEq(amount + swBalBeforeTransfer, swBalAfterTransfer);

        vm.stopPrank();

        // Get the current timestamp for expiry calculation and nonce of Module.
        uint256 expiry = block.timestamp + 100;
        uint256 moduleNonce = allowanceModule.sigNonce();

        (bytes32 moduleTransferHash,) =
            allowanceModule.generateTransferDataAndHash(tokenRecipient, amountTransferrable, expiry, moduleNonce);

        bytes memory sig;

        {
            // Signing for Token Transfer by Secret Wallet.
            (uint8 v0, bytes32 r0, bytes32 s0) = vm.sign(secretWalletPk, moduleTransferHash);

            // Signing for Token Transfer by Hot Wallet.
            (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(hotWalletPk, moduleTransferHash);
            sig = abi.encodePacked(r0, s0, v0, r1, s1, v1);
        }

        // Get the token balance of Token Recipient before transfer by Module.
        uint256 trBalBeforeTransfer = erc20.balanceOf(tokenRecipient);

        vm.prank(coldWallet);
        vm.expectEmit();

        emit allowanceExecuted(coldWallet, address(safe), address(erc20), tokenRecipient, amountTransferrable);

        // Initiate the transaction from Module.
        allowanceModule.executeAllowance(tokenRecipient, amountTransferrable, sig, expiry);

        // Get the token balance of Token Recipient after transfer by Module.
        uint256 trBalAfterTransfer = erc20.balanceOf(tokenRecipient);

        // Check the token balance of Token Recipient is correct.
        assertEq(trBalBeforeTransfer + amountTransferrable, trBalAfterTransfer);

        // Get the token balance of Safe Wallet after transfer by Module.
        uint256 swBalAfterModuleTransfer = erc20.balanceOf(address(safe));

        // Check the token balance of Safe Wallet is correct.
        assertEq(swBalAfterTransfer, swBalAfterModuleTransfer + amountTransferrable);
    }
}
