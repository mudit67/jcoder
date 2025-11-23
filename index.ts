import * as fs from "fs";
import { sign, verify } from "./src/jwt/rsa";

const privateKey = fs.readFileSync("keys/private.pem");
const publicKey = fs.readFileSync("keys/public.pem");

const token = sign({ userId: 123 }, privateKey, {
  algorithm: "RS256",
  expiresIn: "1h",
  issuer: "jwt-from-scratch",
});

console.log(token, "\n");

const payload = verify(token, publicKey, {
  algorithms: ["RS256"],
  issuer: "jwt-from-scratch",
});
console.log(payload);
