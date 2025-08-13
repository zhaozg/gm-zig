// 最简单的加载方式
async function loadWasm() {
  const response = await fetch('/zig-out/bin/gm.wasm');
  const { instance } = await WebAssembly.instantiate(
    await response.arrayBuffer(),
    {} // 空导入对象
  );
  console.log('2 + 3 =', instance.exports.addPoi(2, 3));

  const exports = instance.exports;
  const memory = exports.memory;

  // 2. 准备输入数据
  const inputData = new TextEncoder().encode("Hello, SM3!");

  // 3. 获取输入缓冲区指针
  const inputPtr = exports.getInputBufferPtr();

  // 4. 复制数据到 WASM 内存
  const wasmInputBuffer = new Uint8Array(
    memory.buffer,
    inputPtr,
    inputData.length
  );
  wasmInputBuffer.set(inputData);

  // 5. 执行哈希计算
  exports.sm3Hash(inputData.length);

  // 6. 获取结果
  const outputPtr = exports.getOutputBufferPtr();
  const hashResult = new Uint8Array(
    memory.buffer,
    outputPtr,
    32  // SM3 输出固定32字节
  );

  // 7. 转换为十六进制字符串
  const hexHash = Array.from(hashResult)
  .map(b => b.toString(16).padStart(2, '0'))
  .join('');

  console.log("SM3 Hash:", hexHash);
  document.getElementById("result").textContent = hexHash;
}
loadWasm();
