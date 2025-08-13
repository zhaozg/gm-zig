// server.ts
const server = Bun.serve({
  port: 3000,
  async fetch(request) {
    const path = new URL(request.url).pathname;
    const filePath = path === '/' ? './index.html' : `.${path}`;

    try {
      const file = await Bun.file(filePath);
      if (await file.exists()) {
        return new Response(file);
      }
      return new Response("File not found", { status: 404 });
    } catch (error) {
      return new Response("Error reading file", { status: 500 });
    }
  },
});

console.log(`Serving files from ${process.cwd()} at http://localhost:${server.port}`);
