// A minimal Express service, used to measure what docker-trim actually saves.
const express = require("express");

const app = express();
app.get("/healthz", (_req, res) => res.send("ok\n"));
app.listen(3000, () => console.error("nodeapp listening on :3000"));
