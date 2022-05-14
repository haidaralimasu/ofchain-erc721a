// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "erc721a/contracts/extensions/ERC721AQueryable.sol";

contract NFT is ERC721AQueryable, Ownable, ReentrancyGuard {
    using Strings for uint256;
    using MerkleProof for bytes32;

    uint256 public price = 0.08 ether;
    uint256 public maxNfts = 10000;
    uint256 public maxNftsPerTx = 5;
    uint256 public maxNftsPerAddressLimit = 10;
    uint256 public reservedNfts = 25;
    uint256 public reservedClaimed;

    bool public paused = false;
    bool public presale = true;
    bool public revealed = false;

    string internal hiddenTokenUri;
    string internal baseTokenUri;

    bytes32 public rootHash;

    mapping(address => uint256) public nftsMintedBalance;

    constructor(string memory _hiddenTokenUri, string memory _baseTokenUri)
        ERC721A("NFT", "NFT")
    {
        setHiddenTokenUri(_hiddenTokenUri);
        setBaseTokenUri(_baseTokenUri);
    }

    // Internal
    function _baseURI() internal view virtual override returns (string memory) {
        return baseTokenUri;
    }

    function _mintNfts(address _receiver, uint256 _mintAmount) internal {
        _safeMint(_receiver, _mintAmount);
        nftsMintedBalance[msg.sender] =
            nftsMintedBalance[msg.sender] +
            _mintAmount;
    }

    // Modifiers
    modifier isPaused() {
        require(!paused, "Nft sales is paused currently !!");
        _;
    }

    modifier isPreSale() {
        require(presale, "Nft is live now !!");
        _;
    }

    modifier isPublicSale() {
        require(!presale, "Publicsale is live now !!");
        _;
    }

    modifier mintCompliance(uint256 _mintAmount, address _user) {
        require(
            _mintAmount > 0 && _mintAmount <= maxNftsPerTx,
            "Invalid mint amount !!"
        );
        require(
            totalSupply() + _mintAmount <= maxNfts,
            "NFTs are solded out !!"
        );

        require(
            nftsMintedBalance[_user] + _mintAmount <= maxNftsPerAddressLimit,
            "You cannot mint more Nfts !!"
        );

        _;
    }

    // View Function
    function tokenURI(uint256 tokenId)
        public
        view
        virtual
        override
        returns (string memory)
    {
        require(
            _exists(tokenId),
            "ERC721Metadata: URI query for nonexistent token"
        );

        if (revealed == false) {
            return hiddenTokenUri;
        }

        string memory currentBaseURI = _baseURI();
        return
            bytes(currentBaseURI).length > 0
                ? string(
                    abi.encodePacked(
                        currentBaseURI,
                        tokenId.toString(),
                        ".json"
                    )
                )
                : "";
    }

    // Public Functions
    function mint(uint256 _mintAmount)
        public
        payable
        nonReentrant
        isPaused
        mintCompliance(_mintAmount, msg.sender)
        isPublicSale
    {
        require(
            msg.value >= price * _mintAmount,
            "Insufficient funds to mint !!"
        );
        _mintNfts(msg.sender, _mintAmount);
    }

    function whitelistMint(uint256 _mintAmount, bytes32[] calldata _merkleProof)
        public
        payable
        nonReentrant
        isPaused
        mintCompliance(_mintAmount, msg.sender)
        isPreSale
    {
        require(
            MerkleProof.verify(
                _merkleProof,
                rootHash,
                keccak256(abi.encodePacked(msg.sender))
            ),
            "You are not whitelisted !!"
        );
        require(
            msg.value >= price * _mintAmount,
            "Insufficient funds to mint !!"
        );
        _mintNfts(msg.sender, _mintAmount);
    }

    // Admin only
    function claimReservedNfts(address _receiver, uint256 _amount)
        public
        onlyOwner
    {
        require(
            reservedClaimed <= reservedNfts,
            "You have minted all reserved nfts !!"
        );
        _mintNfts(_receiver, _amount);
        reservedClaimed = reservedClaimed + _amount;
    }

    function reveal() public onlyOwner {
        revealed = true;
    }

    function setNftsPerAddressLimit(uint256 _newLimit) public onlyOwner {
        maxNftsPerAddressLimit = _newLimit;
    }

    function setPrice(uint256 _newPrice) public onlyOwner {
        price = _newPrice * 1 ether;
    }

    function setMaxNftsPerTx(uint256 _newLimit) public onlyOwner {
        maxNftsPerTx = _newLimit;
    }

    function setBaseTokenUri(string memory _newBaseTokenUri) public onlyOwner {
        baseTokenUri = _newBaseTokenUri;
    }

    function setHiddenTokenUri(string memory _newHiddenTokenUri)
        public
        onlyOwner
    {
        hiddenTokenUri = _newHiddenTokenUri;
    }

    function setRootHash(bytes32 _newRootHash) public onlyOwner {
        rootHash = _newRootHash;
    }

    function togglePause() public onlyOwner {
        paused = !paused;
    }

    function togglePresale() public onlyOwner {
        presale = !presale;
    }

    function withdraw() public onlyOwner {
        (bool os, ) = payable(owner()).call{value: address(this).balance}("");
        require(os);
    }
}
