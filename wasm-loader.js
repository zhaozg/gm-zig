// 最简单的加载方式
async function loadWasm() {
  const response = await fetch('/zig-out/bin/gm.wasm');
  const { instance } = await WebAssembly.instantiate(
    await response.arrayBuffer(),
    {} // 空导入对象
  );
  console.log('gmwasm version =', instance.exports.version());

  const exports = instance.exports;

  window.initRandom = function(len = 4096) {
    const array = new Uint8Array(len);
    crypto.getRandomValues(array);

    const rndSeedPtr= exports.alloc(len);
    if (!rndSeedPtr) throw new Error("Allocation failed");

    const rndSeedMem = new Uint8Array(
      exports.memory.buffer,
      rndSeedPtr,
      len
    );
    rndSeedMem.set(array);

    exports.setRandomSeed(rndSeedPtr, len);
    exports.free(rndSeedPtr, len);
  }

  window.random = function(len) {
    const outputPtr = exports.alloc(len);
    if (!outputPtr) throw new Error("Allocation failed");
    exports.getRandomBytes(outputPtr, len);

    const Result = new Uint8Array(
      exports.memory.buffer,
      outputPtr,
      len
    );

    const rndResult = new Uint8Array(Result);
    exports.free(outputPtr, len);

    return rndResult;
  }

  window.sm3hash = function(inputData) {
    const inputPtr = exports.alloc(inputData.length);
    if (!inputPtr) throw new Error("Allocation failed");

    const inputMem = new Uint8Array(
      exports.memory.buffer,
      inputPtr,
      inputData.length
    );
    inputMem.set(inputData);

    // 3. 分配输出内存 (固定 32 字节)
    const outputPtr = exports.alloc(32);
    if (!outputPtr) throw new Error("Allocation failed");

    // 4. 调用 WASM 函数
    exports.sm3hash(inputPtr, inputData.length, outputPtr);

    const hashResult = new Uint8Array(
      exports.memory.buffer,
      outputPtr,
      32
    );

    const finalHash = new Uint8Array(hashResult);

    exports.free(inputPtr, inputData.length);
    exports.free(outputPtr, 32);

    return finalHash;
  }

  window.sm2GenKeyPair = function() {
    const array = new Uint8Array(32);

    const priPtr= exports.alloc(32);
    const pubPtr = exports.alloc(65);
    if (!priPtr) throw new Error("Allocation failed");
    if (!pubPtr) throw new Error("Allocation failed");

    exports.sm2genKeyPair(priPtr, pubPtr);

    const pubKey = new Uint8Array(new Uint8Array(
      exports.memory.buffer,
      pubPtr,
      65
    ));
    const priKey = new Uint8Array(new Uint8Array(
      exports.memory.buffer,
      priPtr,
      32
    ));

    exports.free(pubPtr, 65);
    exports.free(priPtr, 32);

    return {
      "publicKey": pubKey,
      "privateKey": priKey
    };
  }

  window.sm2Sign = function(priKey, msg) {

    const priPtr= exports.alloc(32);
    const msgPtr = exports.alloc(msg.length);
    const sigPtr = exports.alloc(64);
    if (!priPtr) throw new Error("Allocation failed");
    if (!msgPtr) throw new Error("Allocation failed");
    if (!sigPtr) throw new Error("Allocation failed");

    const priMem = new Uint8Array(
      exports.memory.buffer,
      priPtr,
      priKey.length
    );
    priMem.set(priKey);

    const msgMem = new Uint8Array(
      exports.memory.buffer,
      msgPtr,
      msg.length
    );
    msgMem.set(msg);

    exports.sm2sign(priPtr, msgPtr, msg.length, sigPtr);

    const Result = new Uint8Array(
      exports.memory.buffer,
      sigPtr,
      64
    );

    const sigVal = new Uint8Array(Result);

    exports.free(priPtr, 32);
    exports.free(msgPtr, msg.length);
    exports.free(sigPtr, 64);
    return sigVal;
  }

  window.sm2Verify = function(pubKey, msg, sig) {
    const pubPtr = exports.alloc(65);
    const msgPtr = exports.alloc(msg.length);
    const sigPtr = exports.alloc(64);
    if (!pubPtr) throw new Error("Allocation failed");
    if (!msgPtr) throw new Error("Allocation failed");
    if (!sigPtr) throw new Error("Allocation failed");

    const pubMem = new Uint8Array(
      exports.memory.buffer,
      pubPtr,
      pubKey.length
    );
    pubMem.set(pubKey);

    const msgMem = new Uint8Array(
      exports.memory.buffer,
      msgPtr,
      msg.length
    );
    msgMem.set(msg);

    const sigMem = new Uint8Array(
      exports.memory.buffer,
      sigPtr,
      sig.length
    );
    sigMem.set(sig);

    const pass = exports.sm2verify(pubPtr, msgPtr, msg.length, sigPtr);

    exports.free(pubPtr, 65);
    exports.free(msgPtr, msg.length);
    exports.free(sigPtr, msg.length);
    return pass;
  }

  window.sm3hmac = function(key, inputData) {
    const keyPtr= exports.alloc(key.length);
    const inputPtr = exports.alloc(inputData.length);
    if (!inputPtr) throw new Error("Allocation failed");
    if (!keyPtr) throw new Error("Allocation failed");

    const keyMem = new Uint8Array(
      exports.memory.buffer,
      keyPtr,
      key.length
    );
    keyMem.set(key);

    const inputMem = new Uint8Array(
      exports.memory.buffer,
      inputPtr,
      inputData.length
    );
    inputMem.set(inputData);

    // 3. 分配输出内存 (固定 32 字节)
    const outputPtr = exports.alloc(32);
    if (!outputPtr) throw new Error("Allocation failed");

    // 4. 调用 WASM 函数
    exports.sm3hmac(keyPtr, key.length, inputPtr, inputData.length, outputPtr);

    const hashResult = new Uint8Array(
      exports.memory.buffer,
      outputPtr,
      32
    );

    const finalHash = new Uint8Array(hashResult);

    exports.free(inputPtr, inputData.length);
    exports.free(keyPtr, 16);
    exports.free(outputPtr, 32);

    return finalHash;
  }

  window.sm4cbc = function(key, iv, enc, inputData) {
    const keyPtr= exports.alloc(key.length);
    const ivPtr= exports.alloc(iv.length);
    const inputPtr = exports.alloc(inputData.length);
    if (!inputPtr) throw new Error("Allocation failed");
    if (!keyPtr) throw new Error("Allocation failed");
    if (!ivPtr) throw new Error("Allocation failed");

    const keyMem = new Uint8Array(
      exports.memory.buffer,
      keyPtr,
      key.length
    );
    keyMem.set(key);
    const ivMem = new Uint8Array(
      exports.memory.buffer,
      ivPtr,
      iv.length
    );
    ivMem.set(iv);

    const inputMem = new Uint8Array(
      exports.memory.buffer,
      inputPtr,
      inputData.length
    );
    inputMem.set(inputData);

    exports.sm4cbc(keyPtr, ivPtr, enc, inputPtr, inputData.length, inputPtr);

    const Result = new Uint8Array(
      exports.memory.buffer,
      inputPtr,
      inputData.length
    );

    const output = new Uint8Array(Result);

    exports.free(inputPtr, inputData.length);
    exports.free(keyPtr, 16);
    exports.free(ivPtr, 16);

    return output;
  }

  window.initRandom(4096);
}

loadWasm();
