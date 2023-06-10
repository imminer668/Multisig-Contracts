// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract MultiSign is ReentrancyGuard{
    address[] public owners; // 多签名持有人数组
    uint256 public threshold; // 多签名执行阈值：一笔交易必须至少有n个签名才能被执行
    uint256 public nonce; // nonce值：防止签名重放攻击
    mapping(address => bool) public isOwner; // 判断地址是否为多签名持有人
    event ExecutionSuccess(bytes32 txHash); // 交易成功事件
    event ExecutionFailure(bytes32 txHash); // 交易失败事件

    /**
     * @dev 构造函数，初始化所有者、isOwner映射和阈值
     * @param _owners 多签名持有人地址数组
     * @param _threshold 执行交易所需的最小签名数量
     */
    constructor(address[] memory _owners, uint256 _threshold) {
        _setupOwners(_owners, _threshold);
    }
    /**
     * @dev 初始化多签名持有人
     * @param _owners 多签名持有人地址数组
     * @param _threshold 执行交易所需的最小签名数量
     */
    function _setupOwners(
        address[] memory _owners,
        uint256 _threshold
    ) internal {
        // 确保阈值尚未初始化
        require(threshold == 0, "threshold not initialized yet");
        // 确保执行多签名的阈值小于等于多签名持有人数量
        require(_threshold <= _owners.length, "threshold too few");
        // 确保执行多签名的阈值至少为1
        require(_threshold >= 1, "threshold must more than 1");
        for (uint256 i = 0; i < _owners.length; i++) {
            address owner = _owners[i];
            require(
                owner != address(0) &&
                    owner != address(this) &&
                    !isOwner[owner],
                "address error"
            );
            // 多签名持有人不能是零地址，不能是当前合约地址，且不能重复
            owners.push(owner);
            isOwner[owner] = true; // 标记为所有者
        }
        threshold = _threshold; // 设置阈值
    }
    /**
     * @dev 检查签名有效性
     * @param dataHash 待签名数据的哈希
     * @param signatures 签名数据
     */
    function checkSignatures(
        bytes32 dataHash,
        bytes memory signatures
    ) public view {
        require(signatures.length >= threshold * 65, "signatures string error");

        
        address lastOwner = address(0);
        address currentOwner;
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint256 i;
        for (i = 0; i < threshold; i++) {
            // 分离签名数据为v, r, s
            (v, r, s) = signatureSplit(signatures, i);
            // 恢复签名者地址
            currentOwner = ecrecover(
                keccak256(
                    abi.encodePacked(
                        "\x19Ethereum Signed Message:\n32",
                        dataHash
                    )
                ),
                v,
                r,
                s
            );
            // 确保签名者是所有者且按地址排序（防止签名重复）
            require(
                currentOwner > lastOwner && isOwner[currentOwner],
                "signatures error"
            );
            lastOwner = currentOwner;
        }
    }

    /**
     * @dev 分割签名数据
     * @param signatures 签名数据集合
     * @param pos 要分割的签名在集合中的位置
     * @return v 签名的v值
     * @return r 签名的r值
     * @return s 签名的s值
     */
    function signatureSplit(
        bytes memory signatures,
        uint256 pos
    ) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        assembly {
            let signaturePos := mul(0x41, pos)
            r := mload(add(signatures, add(signaturePos, 0x20)))
            s := mload(add(signatures, add(signaturePos, 0x40)))
            v := and(mload(add(signatures, add(signaturePos, 0x41))), 0xff)
        }
    }
    /**
     * @dev 执行交易
     * @param to 目标地址
     * @param value 发送的以太币金额
     * @param data 调用数据
     * @param signatures 签名数据集合
     * @return success 交易是否成功
     */
    function execTransaction(
        address to,
        uint256 value,
        bytes memory data,
        bytes memory signatures
    ) public payable nonReentrant virtual returns (bool success) {
        bytes32 txHash = encodeTransactionData(
            to,
            value,
            data,
            nonce,
            block.chainid
        );
        nonce++; // 增加nonce防止重放攻击
        checkSignatures(txHash, signatures); // 验证签名
        (success, ) = to.call{value: value}(data);
        if (success) emit ExecutionSuccess(txHash);
        else emit ExecutionFailure(txHash);
    }

    /**
     * @dev 编码交易数据
     * @param to 目标地址
     * @param value 发送的以太币金额
     * @param data 调用数据
     * @param _nonce 交易nonce
     * @param chainid 链ID
     * @return 交易数据的哈希值
     */
    function encodeTransactionData(
        address to,
        uint256 value,
        bytes memory data,
        uint256 _nonce,
        uint256 chainid
    ) public pure returns (bytes32) {
        // 计算交易数据的哈希值
        bytes32 safeTxHash = keccak256(
            abi.encode(to, value, keccak256(data), _nonce, chainid)
        );
        return safeTxHash;
    }
    /**
     * @dev 接收以太币函数
     */
    receive() external payable {}
}
