// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract MultiSign {
    constructor() {}
    /**
     * initialize Multiple signature _owners
     * @param _owners : Multiple signature _owners
     * @param _threshold : Minimum number of signatures required to execute a transaction
     */
    function _setupOwners(
        address[] memory _owners,
        uint256 _threshold
    ) internal {}
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
