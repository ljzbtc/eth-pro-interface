import React, { useState } from 'react';
import * as bip39 from 'bip39';
import CryptoJS from 'crypto-js';
import { sha512 } from '@noble/hashes/sha512';
import { bytesToHex } from '@noble/hashes/utils';
import * as secp256k1 from '@noble/secp256k1';



// 改进的 hexToBytes 函数
function hexToBytes(hex) {
  if (typeof hex !== 'string') {
    throw new Error('Input must be a string');
  }
  hex = hex.replace(/^0x/, '');  // 移除可能的 "0x" 前缀
  if (hex.length % 2 !== 0) {
    throw new Error('Hex string must have an even number of characters');
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

// 新增的 Helper 函数: 字节数组转换为 BigInt
function bytesToBigInt(bytes) {
  return BigInt('0x' + bytesToHex(bytes));
}

// 新增的 Helper 函数: BigInt 转换为字节数组
function bigIntToBytes(number, length) {
  return hexToBytes(number.toString(16).padStart(length * 2, '0'));
}

function WalletGenerator() {
  const [randomIntegers, setRandomIntegers] = useState(null);
  const [entropyHex, setEntropyHex] = useState(null);
  const [checksum, setChecksum] = useState(null);
  const [entropyWithChecksum, setEntropyWithChecksum] = useState(null);
  const [binaryGroups, setBinaryGroups] = useState(null);
  const [mnemonic, setMnemonic] = useState(null);
  const [seed, setSeed] = useState(null);
  const [masterPrivateKey, setMasterPrivateKey] = useState(null);
  const [masterChainCode, setMasterChainCode] = useState(null);
  const [addresses, setAddresses] = useState([]);

  const wordlist = bip39.wordlists.english;

  async function generateWallet() {
    // Step 1: Generate 128-bit random seed
    const array = new Uint32Array(4);
    crypto.getRandomValues(array);
    const newRandomIntegers = Array.from(array);
    setRandomIntegers(newRandomIntegers);

    // Step 2: Convert to hexadecimal
    const newEntropyHex = newRandomIntegers.map(num => num.toString(16).padStart(8, '0')).join('');
    setEntropyHex(newEntropyHex);

    // Step 3: Calculate checksum
    const entropyBytes = CryptoJS.enc.Hex.parse(newEntropyHex);
    const hashBytes = CryptoJS.SHA256(entropyBytes);
    const hashHex = hashBytes.toString(CryptoJS.enc.Hex);
    const newChecksum = hashHex.slice(0, 1);
    setChecksum(newChecksum);

    // Step 4: Combine entropy and checksum
    const newEntropyWithChecksum = newEntropyHex + newChecksum;
    setEntropyWithChecksum(newEntropyWithChecksum);

    // Step 5: Split into 11-bit groups
    const binary = BigInt(`0x${newEntropyWithChecksum}`).toString(2).padStart(132, '0');
    const groups = [];
    for (let i = 0; i < 12; i++) {
      const group = binary.slice(i * 11, (i + 1) * 11);
      const index = parseInt(group, 2);
      const word = wordlist[index];
      groups.push({ binary: group, decimal: index, word: word });
    }
    setBinaryGroups(groups);

    // Step 6: Generate mnemonic
    const newMnemonic = bip39.entropyToMnemonic(newEntropyHex);
    setMnemonic(newMnemonic);

    // Step 7: Generate seed from mnemonic
    const newSeed = await bip39.mnemonicToSeed(newMnemonic);
    setSeed(newSeed.toString('hex'));

    const seed = await bip39.mnemonicToSeed(mnemonic);
    console.log('Seed:', seed, typeof seed);
    const hmac = sha512(new TextEncoder().encode('Bitcoin seed'), seed);
    const masterPrivKey = hmac.slice(0, 32);
    const masterChainCode = hmac.slice(32);
    console.log('Master Private Key:', masterPrivKey, typeof masterPrivKey);
    console.log('Master Chain Code:', masterChainCode, typeof masterChainCode);
    setMasterPrivateKey(bytesToHex(masterPrivKey));
    setMasterChainCode(bytesToHex(masterChainCode));

    // 步骤9: 生成子密钥和地址
    const newAddresses = [];
    let parentPrivateKey = hexToBytes(masterPrivateKey);
    let parentChainCode = hexToBytes(masterChainCode);
    for (let i = 0; i < 5; i++) {
      const { privateKey, publicKey, chainCode } = deriveChildKeyPair(parentPrivateKey, parentChainCode, i);
      const address = getEthereumAddress(publicKey);
      newAddresses.push(address);
      // 更新父私钥和链码为当前子密钥，以便进行下一次派生
      parentPrivateKey = privateKey;
      parentChainCode = chainCode;
    }
    setAddresses(newAddresses);
  }

  function bytesToBigInt(bytes) {
    return BigInt('0x' + bytesToHex(bytes));
  }

  // 新增的 Helper 函数: BigInt 转换为字节数组
  function bigIntToBytes(number, length) {
    return hexToBytes(number.toString(16).padStart(length * 2, '0'));
  }

  // 更新的 Helper 函数: 派生子密钥对
  function deriveChildKeyPair(parentPrivateKey, parentChainCode, index) {
    const indexBuffer = new Uint8Array(4);
    new DataView(indexBuffer.buffer).setUint32(0, index);
    const data = new Uint8Array([...parentPrivateKey, ...indexBuffer]);
    const I = sha512(parentChainCode, data);
    
    const IL = I.slice(0, 32);
    const IR = I.slice(32);
    
    const parentPrivateKeyBigInt = bytesToBigInt(parentPrivateKey);
    const ILBigInt = bytesToBigInt(IL);
    
    const childPrivateKeyBigInt = (ILBigInt + parentPrivateKeyBigInt) % BigInt(secp256k1.CURVE.n);
    
    const childPrivateKey = bigIntToBytes(childPrivateKeyBigInt, 32);
    const childPublicKey = secp256k1.getPublicKey(childPrivateKey, true);
    
    return { privateKey: childPrivateKey, publicKey: childPublicKey, chainCode: IR };
  }

  // 更新的 Helper 函数: 从公钥生成以太坊地址
  function getEthereumAddress(publicKey) {
    // 移除公钥的第一个字节（0x04，表示未压缩的公钥）
    const publicKeyWithoutPrefix = publicKey.slice(1);
    const hash = CryptoJS.SHA3(bytesToHex(publicKeyWithoutPrefix), { outputLength: 256 });
    return '0x' + hash.toString(CryptoJS.enc.Hex).slice(-40);
  }


  return (
    <div style={{fontFamily: 'Arial, sans-serif', maxWidth: '800px', margin: '0 auto', padding: '20px'}}>
      <h1 style={{textAlign: 'center'}}>Comprehensive HD Wallet Generator</h1>
      <button onClick={generateWallet} style={{display: 'block', margin: '20px auto', padding: '10px 20px', fontSize: '16px', backgroundColor: '#4CAF50', color: 'white', border: 'none', borderRadius: '5px', cursor: 'pointer'}}>
        Generate Wallet
      </button>

      <div style={{backgroundColor: '#f0f0f0', padding: '20px', borderRadius: '5px', marginTop: '20px'}}>
        <h2>Step 1: Generate 128-bit Random Seed (4 x 32-bit integers)</h2>
        {randomIntegers ? (
          <ul>
            {randomIntegers.map((num, index) => (
              <li key={index}>
                Integer {index + 1}: {num} (Hex: {num.toString(16).padStart(8, '0')})
              </li>
            ))}
          </ul>
        ) : (
          <p>Not generated</p>
        )}
      </div>

      <div style={{backgroundColor: '#e6e6e6', padding: '20px', borderRadius: '5px', marginTop: '20px'}}>
        <h2>Step 2: Combine into 32-character Hexadecimal String (Entropy)</h2>
        <p>Entropy Hex (128 bits): {entropyHex || 'Not generated'}</p>
      </div>

      <div style={{backgroundColor: '#f0f0f0', padding: '20px', borderRadius: '5px', marginTop: '20px'}}>
        <h2>Step 3: Calculate Checksum (first 4 bits of SHA256 hash of entropy)</h2>
        <p>Checksum: {checksum || 'Not generated'}</p>
      </div>

      <div style={{backgroundColor: '#e6e6e6', padding: '20px', borderRadius: '5px', marginTop: '20px'}}>
        <h2>Step 4: Combine Entropy with Checksum</h2>
        <p>Entropy + Checksum (132 bits): {entropyWithChecksum || 'Not generated'}</p>
      </div>

      <div style={{backgroundColor: '#f0f0f0', padding: '20px', borderRadius: '5px', marginTop: '20px'}}>
        <h2>Step 5: Split into 11-bit Groups and Map to Words</h2>
        {binaryGroups ? (
          <ul>
            {binaryGroups.map((group, index) => (
              <li key={index}>
                Group {index + 1}: {group.binary} 
                (Decimal: {group.decimal}, Word: <strong>{group.word}</strong>)
              </li>
            ))}
          </ul>
        ) : (
          <p>Not generated</p>
        )}
      </div>

      <div style={{backgroundColor: '#e6e6e6', padding: '20px', borderRadius: '5px', marginTop: '20px'}}>
        <h2>Step 6: Final Mnemonic</h2>
        <p style={{fontWeight: 'bold', wordBreak: 'break-all'}}>{mnemonic || 'Not generated'}</p>
      </div>

      <div style={{backgroundColor: '#f0f0f0', padding: '20px', borderRadius: '5px', marginTop: '20px'}}>
        <h2>Step 7: Generate Seed from Mnemonic</h2>
        <p style={{wordBreak: 'break-all'}}>Seed (hex): {seed ? seed : 'Not generated'}</p>
      </div>

      <div style={{backgroundColor: '#e6e6e6', padding: '20px', borderRadius: '5px', marginTop: '20px'}}>
        <h2>Step 8: Generate Master Private Key and Chain Code</h2>
        <p style={{wordBreak: 'break-all'}}>Master Private Key: {masterPrivateKey ? masterPrivateKey : 'Not generated'}</p>
        <p style={{wordBreak: 'break-all'}}>Master Chain Code: {masterChainCode ? masterChainCode : 'Not generated'}</p>
      </div>

      <div style={{backgroundColor: '#f0f0f0', padding: '20px', borderRadius: '5px', marginTop: '20px'}}>
        <h2>Step 9: Generate Child Keys and Addresses</h2>
        {addresses.length > 0 ? (
          <ul>
            {addresses.map((address, index) => (
              <li key={index}>Address {index}: {address}</li>
            ))}
          </ul>
        ) : (
          <p>Not generated</p>
        )}
      </div>
    </div>
  );
}

export default WalletGenerator;