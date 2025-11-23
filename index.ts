import * as dotenv from "dotenv";
import jwt from "./models/jwt";
dotenv.config({ quiet: true });

// Destructure to get HMAC directly

const secret = process.env.JWT_SECRET;

const token = jwt.HMAC.sign({ userId: 123 }, secret!, {
  algorithm: "HS256",
  expiresIn: "1h",
  issuer: "jwt-from-scratch",
});

console.log("JWT:", token);

try {
  const payload = jwt.HMAC.verify(token, secret!, {
    algorithms: ["HS256"],
    issuer: "jwt-from-scratch",
  });
  console.log("Verified payload:", payload);
} catch (err) {
  console.error((err as Error).name, (err as Error).message);
}
