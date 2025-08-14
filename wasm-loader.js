// 最简单的加载方式
async function loadWasm() {
  const response = await fetch('/zig-out/bin/gm.wasm');
  const { instance } = await WebAssembly.instantiate(
    await response.arrayBuffer(),
    {} // 空导入对象
  );
  console.log('gmwasm version =', instance.exports.version());

  const exports = instance.exports;

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
}

loadWasm();
