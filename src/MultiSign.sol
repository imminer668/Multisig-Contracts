// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract MultiSign is ReentrancyGuard{
    address[] public owners; // 多签名持有人数组
    uint256 public threshold; // 多签名执行阈值：一笔交易必须至少有n个签名才能被执行
    uint256 public nonce; // nonce值：防止签名重放攻击
    mapping(address => bool) public isOwner; // 判断地址是否为多签名持有人
    
    // 交易结构体
    struct Transaction {
        address to;         // 目标地址
        uint256 value;      // 发送的以太币金额
        bytes data;         // 调用数据
        bool executed;      // 是否已执行
        uint256 timestamp;  // 创建时间戳
        bool cancelled;     // 是否已取消
    }
    
    // 存储交易记录
    mapping(bytes32 => Transaction) public transactions;
    
    // 交易有效期（默认30天）
    uint256 public transactionValidityPeriod = 30 days;
    
    // 事件定义
    event ExecutionSuccess(bytes32 txHash); // 交易成功事件
    event ExecutionFailure(bytes32 txHash); // 交易失败事件
    event TransactionCancelled(bytes32 txHash); // 交易取消事件
    event OwnerAdded(address indexed owner); // 添加所有者事件
    event OwnerRemoved(address indexed owner); // 移除所有者事件
    event ThresholdChanged(uint256 threshold); // 阈值修改事件
    event TransactionValidityPeriodChanged(uint256 period); // 交易有效期修改事件
    event TransactionSubmitted(
        bytes32 indexed txHash,
        address to,
        uint256 value,
        bytes data,
        uint256 nonce
    ); // 交易提交事件

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

        // 通过一个循环，检查收集的签名是否有效
         // 大概思路：
         // 1. 用ecdsa先验证签名是否有效
         // 2. 利用 currentOwner > lastOwner 确定签名来自不同多签（多签地址递增）
         // 3. 利用 isOwner[currentOwner] 确定签名者为多签持有人
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
     * @dev 提交交易，但不立即执行
     * @param to 目标地址
     * @param value 发送的以太币金额
     * @param data 调用数据
     * @return txHash 交易哈希
     */
    function submitTransaction(
        address to,
        uint256 value,
        bytes memory data
    ) public returns (bytes32 txHash) {
        require(isOwner[msg.sender], "not an owner");
        require(to != address(0), "invalid target address");
        
        txHash = encodeTransactionData(
            to,
            value,
            data,
            nonce,
            block.chainid
        );
        
        // 确保交易尚未存在
        require(transactions[txHash].timestamp == 0, "transaction already exists");
        
        // 创建新交易
        transactions[txHash] = Transaction({
            to: to,
            value: value,
            data: data,
            executed: false,
            timestamp: block.timestamp,
            cancelled: false
        });
        
        // 递增nonce
        nonce++;
        
        // 触发事件
        emit TransactionSubmitted(txHash, to, value, data, nonce - 1);
        
        return txHash;
    }
    
    /**
     * @dev 取消交易
     * @param txHash 交易哈希
     */
    function cancelTransaction(bytes32 txHash) public {
        require(isOwner[msg.sender], "not an owner");
        
        Transaction storage transaction = transactions[txHash];
        
        // 检查交易是否存在
        require(transaction.timestamp > 0, "transaction does not exist");
        
        // 检查交易是否已执行
        require(!transaction.executed, "transaction already executed");
        
        // 检查交易是否已取消
        require(!transaction.cancelled, "transaction already cancelled");
        
        // 标记为已取消
        transaction.cancelled = true;
        
        // 触发事件
        emit TransactionCancelled(txHash);
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
        
        // 检查交易记录
        Transaction storage transaction = transactions[txHash];
        
        // 如果交易已经提交过
        if (transaction.timestamp > 0) {
            // 检查交易是否已执行
            require(!transaction.executed, "transaction already executed");
            
            // 检查交易是否已取消
            require(!transaction.cancelled, "transaction cancelled");
            
            // 检查交易是否在有效期内
            require(
                block.timestamp <= transaction.timestamp + transactionValidityPeriod,
                "transaction expired"
            );
        } else {
            // 如果是直接执行而不是先提交，则创建一个新的交易记录
            transactions[txHash] = Transaction({
                to: to,
                value: value,
                data: data,
                executed: false,
                timestamp: block.timestamp,
                cancelled: false
            });
            
            emit TransactionSubmitted(txHash, to, value, data, nonce);
        }
        
        nonce++; // 增加nonce防止重放攻击
        checkSignatures(txHash, signatures); // 验证签名
        
        // 标记为已执行
        transactions[txHash].executed = true;
        
        // 执行交易
        (success, ) = to.call{value: value}(data);
        
        if (success) emit ExecutionSuccess(txHash);
        else emit ExecutionFailure(txHash);
    }

    /**
     * @dev 获取交易信息
     * @param txHash 交易哈希
     * @return to 目标地址
     * @return value 以太币金额
     * @return data 调用数据
     * @return executed 是否已执行
     * @return timestamp 创建时间戳
     * @return cancelled 是否已取消
     */
    function getTransaction(bytes32 txHash) public view returns (
        address to,
        uint256 value,
        bytes memory data,
        bool executed,
        uint256 timestamp,
        bool cancelled
    ) {
        Transaction storage transaction = transactions[txHash];
        return (
            transaction.to,
            transaction.value,
            transaction.data,
            transaction.executed,
            transaction.timestamp,
            transaction.cancelled
        );
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
     * @dev 添加所有者
     * @param owner 新所有者地址
     * @param signatures 签名数据
     */
    function addOwner(address owner, bytes memory signatures) public {
        // 编码操作数据
        bytes32 dataHash = keccak256(
            abi.encodePacked("addOwner", owner, nonce, block.chainid)
        );
        
        // 验证签名
        checkSignatures(dataHash, signatures);
        
        // 验证新所有者地址
        require(
            owner != address(0) && 
            owner != address(this) && 
            !isOwner[owner], 
            "invalid owner"
        );
        
        // 添加新所有者
        isOwner[owner] = true;
        owners.push(owner);
        
        // 递增nonce
        nonce++;
        
        // 触发事件
        emit OwnerAdded(owner);
    }
    
    /**
     * @dev 移除所有者
     * @param owner 要移除的所有者地址
     * @param signatures 签名数据
     */
    function removeOwner(address owner, bytes memory signatures) public {
        // 编码操作数据
        bytes32 dataHash = keccak256(
            abi.encodePacked("removeOwner", owner, nonce, block.chainid)
        );
        
        // 验证签名
        checkSignatures(dataHash, signatures);
        
        // 验证所有者身份
        require(isOwner[owner], "not an owner");
        
        // 确保移除后的所有者数量不小于阈值
        require(owners.length > threshold, "cannot have fewer owners than threshold");
        
        // 移除所有者
        isOwner[owner] = false;
        
        // 从数组中删除
        for (uint256 i = 0; i < owners.length; i++) {
            if (owners[i] == owner) {
                owners[i] = owners[owners.length - 1];
                owners.pop();
                break;
            }
        }
        
        // 递增nonce
        nonce++;
        
        // 触发事件
        emit OwnerRemoved(owner);
    }
    
    /**
     * @dev 修改阈值
     * @param _threshold 新阈值
     * @param signatures 签名数据
     */
    function changeThreshold(uint256 _threshold, bytes memory signatures) public {
        // 编码操作数据
        bytes32 dataHash = keccak256(
            abi.encodePacked("changeThreshold", _threshold, nonce, block.chainid)
        );
        
        // 验证签名
        checkSignatures(dataHash, signatures);
        
        // 验证阈值
        require(_threshold > 0, "threshold cannot be zero");
        require(_threshold <= owners.length, "threshold cannot exceed owner count");
        
        // 更新阈值
        threshold = _threshold;
        
        // 递增nonce
        nonce++;
        
        // 触发事件
        emit ThresholdChanged(_threshold);
    }
    
    /**
     * @dev 修改交易有效期
     * @param period 新的有效期（秒）
     * @param signatures 签名数据
     */
    function setTransactionValidityPeriod(uint256 period, bytes memory signatures) public {
        // 编码操作数据
        bytes32 dataHash = keccak256(
            abi.encodePacked("setValidityPeriod", period, nonce, block.chainid)
        );
        
        // 验证签名
        checkSignatures(dataHash, signatures);
        
        // 验证有效期（至少1小时，最多1年）
        require(period >= 1 hours, "period too short");
        require(period <= 365 days, "period too long");
        
        // 更新有效期
        transactionValidityPeriod = period;
        
        // 递增nonce
        nonce++;
        
        // 触发事件
        emit TransactionValidityPeriodChanged(period);
    }
    
    /**
     * @dev 获取所有所有者
     * @return 所有者地址数组
     */
    function getOwners() public view returns (address[] memory) {
        return owners;
    }
    
    /**
     * @dev 获取所有者数量
     * @return 所有者数量
     */
    function getOwnerCount() public view returns (uint256) {
        return owners.length;
    }

    /**
     * @dev 接收以太币函数
     */
    receive() external payable {}
}
