import { generateKeyPairSync, createECDH, publicEncrypt, createHash } from "node:crypto";

const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const ecdh = createECDH("prime256v1");
const sealed = publicEncrypt(publicKey, Buffer.from("secret"));
const etag = createHash("sha1").update("x").digest("hex");

export async function sign(data: ArrayBuffer) {
  const key = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
  return key;
}
