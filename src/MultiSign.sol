// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract MultiSign {
    address[] public owners; // Multi-signature holder array
    uint256 public threshold; // Multi-signature execution threshold: A transaction must have at least n signatures before it can be executed.
    uint256 public nonce; // nonce: prevents signature replay attacks
    event ExecutionSuccess(bytes32 txHash); // Transaction success event
    event ExecutionFailure(bytes32 txHash); // Transaction failure event

    // constructor, initializes owners, isOwner, ownerCount, threshold
    constructor(address[] memory _owners, uint256 _threshold) {
        _setupOwners(_owners, _threshold);
    }
    /**
     * initialize Multiple signature _owners
     * @param _owners : Multiple signature _owners
     * @param _threshold : Minimum number of signatures required to execute a transaction
     */
    function _setupOwners(
        address[] memory _owners,
        uint256 _threshold
    ) internal {
        // threshold was not initialized
        require(threshold == 0, "threshold not initialized yet");
        // The threshold for executing multiple signatures is smaller than the number of multiple signatures
        require(_threshold <= _owners.length, "threshold too few");
        // The threshold for executing multiple signatures must be at least 1
        require(_threshold >= 1, "threshold must more than 1");
        for (uint256 i = 0; i < _owners.length; i) {
            address owner = _owners[i];
            // Multiple signers cannot be 0 addresses, and the address of this contract cannot be repeated
            owners.push(owner);
        }
    }
    /**
     * check signatures
     * @param dataHash : Hash of the data to be signed
     * @param signatures : Signatures of the data
     */
    function checkSignatures(
        bytes32 dataHash,
        bytes memory signatures
    ) public view {}

    /**
     * split signature
     * @param signatures : Signatures of the data
     * @param pos : Position of the signature to be split
     */
    function signatureSplit(
        bytes memory signatures,
        uint256 pos
    ) internal pure returns (uint8 v, bytes32 r, bytes32 s) {}
    /**
     * execute transaction
     * @param to : Address to execute
     * @param value : Value to execute
     * @param data : Data to execute
     * @param signatures : Signatures of the data
     */
    function execTransaction(
        address to,
        uint256 value,
        bytes memory data,
        bytes memory signatures
    ) public payable virtual returns (bool success) {}

    /**
     * encode transaction data
     * @param to : Address to send the transaction
     * @param value : Amount of Ether to send
     * @param data : Data to send
     * @param _nonce : Nonce of the transaction
     * @param chainid : Chain ID of the transaction
     */
    function encodeTransactionData(
        address to,
        uint256 value,
        bytes memory data,
        uint256 _nonce,
        uint256 chainid
    ) public pure returns (bytes32) {
        //
        bytes32 safeTxHash = keccak256(
            abi.encode(to, value, keccak256(data), _nonce, chainid)
        );
        return safeTxHash;
    }
    receive() external payable {}
}
