// 最简单的加载方式
async function loadWasm() {
  const response = await fetch('/zig-out/bin/gm.wasm');
  const { instance } = await WebAssembly.instantiate(
    await response.arrayBuffer(),
    {} // 空导入对象
  );
  console.log('gmwasm version =', instance.exports.version());

  const exports = instance.exports;

  window.sm3hash = async function computeSM3(inputData) {
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
}

loadWasm();
