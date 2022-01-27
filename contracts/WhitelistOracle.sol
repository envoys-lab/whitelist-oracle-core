// SPDX-License-Identifier: MIT
pragma solidity >=0.4.22 <0.9.0;

contract WhitelistOracle {
  event ManagerStatusChanged(
    address account,
    bool status
  );

  event VerifyStatusChanged(
    address account,
    bool status,
    uint256 nonce
  );

  address public owner = msg.sender;
  mapping(address => bool) public managers;
  mapping(address => bool) public verified;
  mapping (address => uint256) public nonce;

  modifier onlyManager {
    require(managers[msg.sender] || owner == msg.sender, "MANAGER_REQUIRED");
    _;
  }

  modifier onlyOwner {
    require(owner == msg.sender, "OWNER_REQUIRED");
    _;
  }

  constructor() {
    managers[msg.sender] = true;
  }

  function transferOwnership(address _account) external onlyOwner {
    owner = _account;
  }

  function setManager(address _account, bool _status) external onlyOwner {
    managers[_account] = _status;
    emit ManagerStatusChanged(_account, _status);
  }

  function verifiy(address _account, bool _status) external onlyManager {
    _verifiy(_account, _status);
  }

  function _verifiy(address _account, bool _status) private {
    verified[_account] = _status;
    emit VerifyStatusChanged(_account, _status, nonce[_account]++);
  }

  function getMessageHash(
    address _account,
    bool _status
  ) public pure returns (bytes32) {
    return keccak256(abi.encodePacked(_account, _status));
  }

  function getEthSignedMessageHash(bytes32 _messageHash)
    public
    pure
    returns (bytes32)
  {

    return
      keccak256(
        abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash)
      );
  }

  function recoverSigner(bytes32 _ethSignedMessageHash, bytes memory _signature)
    public
    pure
    returns (address)
  {
    (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);

    return ecrecover(_ethSignedMessageHash, v, r, s);
  }

  function splitSignature(bytes memory sig)
    public
    pure
    returns (
        bytes32 r,
        bytes32 s,
        uint8 v
    )
  {
    require(sig.length == 65, "SIGNATURE_LEN_INVALID");

    assembly {
        r := mload(add(sig, 32))
        s := mload(add(sig, 64))
        v := byte(0, mload(add(sig, 96)))
    }

  }

  function delegatedVerify(
      address _account, 
      bool _status, 
      uint256 _nonce,
      bytes memory _signature
    ) external {
    require(nonce[_account] == _nonce, "NONCE_INVALID");

    bytes32 messageHash = getMessageHash(_account, _status);
    bytes32 ethSignedMessageHash = getEthSignedMessageHash(messageHash);

    require(
      managers[recoverSigner(ethSignedMessageHash, _signature)],
      "SIGNATURE_INVALID"
    );

    _verifiy(_account, _status);
  }
}
