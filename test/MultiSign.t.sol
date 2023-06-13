// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {MultiSign} from "../src/MultiSign.sol";

contract MultiSignTest is Test {
    MultiSign public multiSign;
    
    // 测试账户
    address[] public owners;
    uint256 public threshold = 2;
    
    // 测试签名私钥
    uint256 private ownerPK1 = 0x1;
    uint256 private ownerPK2 = 0x2;
    uint256 private ownerPK3 = 0x3;
    // 非多签账户
    uint256 private nonOwnerPK = 0x4;
    
    // 预先计算的地址
    address public owner1;
    address public owner2;
    address public owner3;
    address public nonOwner;

    function setUp() public {
        // 初始化测试账户
        owner1 = vm.addr(ownerPK1);
        owner2 = vm.addr(ownerPK2);
        owner3 = vm.addr(ownerPK3);
        nonOwner = vm.addr(nonOwnerPK);
        
        // 准备所有者数组
        owners = new address[](3);
        owners[0] = owner1;
        owners[1] = owner2;
        owners[2] = owner3;
        
        // 部署多签名合约
        multiSign = new MultiSign(owners, threshold);
    }
    
    // 测试初始化是否正确
    function testInitialization() public {
        // 检查阈值设置
        assertEq(multiSign.threshold(), threshold);
        
        // 检查所有者数量
        assertEq(multiSign.owners(0), owner1);
        assertEq(multiSign.owners(1), owner2);
        assertEq(multiSign.owners(2), owner3);
        
        // 检查所有者映射
        assertTrue(multiSign.isOwner(owner1));
        assertTrue(multiSign.isOwner(owner2));
        assertTrue(multiSign.isOwner(owner3));
        assertFalse(multiSign.isOwner(nonOwner));
    }
    
    // 辅助函数：生成签名
    function signMessage(bytes32 message, uint256 privateKey) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", message)));
        return abi.encodePacked(r, s, v);
    }
    
    // 辅助函数：合并多个签名
    function combineSignatures(bytes[] memory signatures) internal pure returns (bytes memory) {
        bytes memory combined = "";
        for (uint256 i = 0; i < signatures.length; i++) {
            combined = abi.encodePacked(combined, signatures[i]);
        }
        return combined;
    }
    
    // 测试基本交易执行
    function testExecTransaction() public {
        // 向多签名合约发送一些ETH
        vm.deal(address(multiSign), 10 ether);
        
        // 准备交易数据
        address to = address(0x123);
        uint256 value = 1 ether;
        bytes memory data = "";
        
        // 生成交易哈希
        bytes32 txHash = multiSign.encodeTransactionData(
            to, 
            value, 
            data, 
            multiSign.nonce(), 
            block.chainid
        );
        
        // 生成签名
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = signMessage(txHash, ownerPK1);
        sigs[1] = signMessage(txHash, ownerPK2);
        
        // 排序签名（依据恢复出的地址）
        address addr1 = vm.addr(ownerPK1);
        address addr2 = vm.addr(ownerPK2);
        
        if (addr1 > addr2) {
            bytes memory temp = sigs[0];
            sigs[0] = sigs[1];
            sigs[1] = temp;
        }
        
        bytes memory signatures = combineSignatures(sigs);
        
        // 执行交易
        uint256 initialBalance = address(to).balance;
        bool success = multiSign.execTransaction(to, value, data, signatures);
        
        // 验证结果
        assertTrue(success);
        assertEq(address(to).balance, initialBalance + value);
    }
    
    // 测试签名验证失败（签名不足）
    function testInsufficientSignatures() public {
        address to = address(0x123);
        uint256 value = 1 ether;
        bytes memory data = "";
        
        bytes32 txHash = multiSign.encodeTransactionData(
            to, 
            value, 
            data, 
            multiSign.nonce(), 
            block.chainid
        );
        
        // 只有一个签名，但阈值为2
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = signMessage(txHash, ownerPK1);
        bytes memory signatures = combineSignatures(sigs);
        
        // 预期执行失败
        vm.expectRevert("signatures string error");
        multiSign.execTransaction(to, value, data, signatures);
    }
    
    // 测试非法签名（非所有者签名）
    function testInvalidSignature() public {
        address to = address(0x123);
        uint256 value = 1 ether;
        bytes memory data = "";
        
        bytes32 txHash = multiSign.encodeTransactionData(
            to, 
            value, 
            data, 
            multiSign.nonce(), 
            block.chainid
        );
        
        // 一个有效签名和一个无效签名
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = signMessage(txHash, ownerPK1);
        sigs[1] = signMessage(txHash, nonOwnerPK); // 非所有者签名
        
        // 排序签名
        address addr1 = vm.addr(ownerPK1);
        address addrNon = vm.addr(nonOwnerPK);
        
        if (addr1 > addrNon) {
            bytes memory temp = sigs[0];
            sigs[0] = sigs[1];
            sigs[1] = temp;
        }
        
        bytes memory signatures = combineSignatures(sigs);
        
        // 预期执行失败
        vm.expectRevert("signatures error");
        multiSign.execTransaction(to, value, data, signatures);
    }
    
    // 测试签名排序错误
    function testSignatureOrder() public {
        // 向多签名合约发送一些ETH
        vm.deal(address(multiSign), 10 ether);
        address to = address(0x123);
        uint256 value = 1 ether;
        bytes memory data = "";
        
        bytes32 txHash = multiSign.encodeTransactionData(
            to, 
            value, 
            data, 
            multiSign.nonce(), 
            block.chainid
        );
        
        // 生成签名
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = signMessage(txHash, ownerPK1);
        sigs[1] = signMessage(txHash, ownerPK2);
        
        // 确保签名顺序错误 - 合约要求按地址升序排列
        address addr1 = vm.addr(ownerPK1);
        address addr2 = vm.addr(ownerPK2);
        
        // 第一步：先确保签名按照正确的升序排列
        if (addr1 > addr2) {
            // 如果addr1大于addr2，则需要交换以确保升序
            bytes memory temp = sigs[0];
            sigs[0] = sigs[1];
            sigs[1] = temp;
        }
        
        // 第二步：故意将正确排序的签名反转，制造错误的降序排列
        // 这应该会导致合约验证失败
        bytes memory temp = sigs[0];
        sigs[0] = sigs[1];
        sigs[1] = temp;
        
        bytes memory signatures = combineSignatures(sigs);
        
        // 预期执行失败，合约会检测到签名未按地址升序排列
        vm.expectRevert("signatures error");
        multiSign.execTransaction(to, value, data, signatures);
    }
    
    // 测试nonce递增
    function testNonceIncrement() public {
        // 向多签名合约发送一些ETH
        vm.deal(address(multiSign), 10 ether);
        
        // 准备交易数据
        address to = address(0x123);
        uint256 value = 1 ether;
        bytes memory data = "";
        
        // 记录初始nonce
        uint256 initialNonce = multiSign.nonce();
        
        // 第一笔交易
        bytes32 txHash1 = multiSign.encodeTransactionData(
            to, 
            value, 
            data, 
            initialNonce, 
            block.chainid
        );
        
        // 生成签名
        bytes[] memory sigs1 = new bytes[](2);
        sigs1[0] = signMessage(txHash1, ownerPK1);
        sigs1[1] = signMessage(txHash1, ownerPK2);
        
        // 排序签名
        address addr1 = vm.addr(ownerPK1);
        address addr2 = vm.addr(ownerPK2);
        
        if (addr1 > addr2) {
            bytes memory temp = sigs1[0];
            sigs1[0] = sigs1[1];
            sigs1[1] = temp;
        }
        
        bytes memory signatures1 = combineSignatures(sigs1);
        
        // 执行第一笔交易
        multiSign.execTransaction(to, value, data, signatures1);
        
        // 检查nonce是否增加
        assertEq(multiSign.nonce(), initialNonce + 1);
        
        // 尝试重放第一笔交易
        vm.expectRevert(); // 预期会失败，但不确定具体错误信息
        multiSign.execTransaction(to, value, data, signatures1);
        
        // 准备第二笔交易，使用新的nonce
        bytes32 txHash2 = multiSign.encodeTransactionData(
            to, 
            value, 
            data, 
            multiSign.nonce(), 
            block.chainid
        );
        
        // 生成新的签名
        bytes[] memory sigs2 = new bytes[](2);
        sigs2[0] = signMessage(txHash2, ownerPK1);
        sigs2[1] = signMessage(txHash2, ownerPK2);
        
        // 排序签名
        if (addr1 > addr2) {
            bytes memory temp = sigs2[0];
            sigs2[0] = sigs2[1];
            sigs2[1] = temp;
        }
        
        bytes memory signatures2 = combineSignatures(sigs2);
        
        // 执行第二笔交易
        multiSign.execTransaction(to, value, data, signatures2);
        
        // 检查nonce是否再次增加
        assertEq(multiSign.nonce(), initialNonce + 2);
    }
}
