import React, { useState } from "react";
import { useNavigate } from "react-router-dom";

export default function Login() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [algo, setAlgo] = useState("HMAC"); // "HMAC" or "RSA"
  const [useRefresh, setUseRefresh] = useState(false);
  const [expiresIn, setExpiresIn] = useState("3600");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const res = await fetch("http:localhost:3000/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username,
          password,
          algorithm: algo,
          issueRefreshToken: useRefresh,
        }),
      });

      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.message || "Login failed");
      }
      const result = await res.json();
      localStorage.setItem("accessToken", result.token);
      localStorage.setItem("data", JSON.stringify({"username":result.data.username, "issuedAt":result.issuedAt}))

      navigate("/dashboard");
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <form className="form-grid" onSubmit={handleSubmit}>
      <div>
        <div className="label">Username</div>
        <input
          className="input"
          type="username"
          placeholder="you@example.com"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          required
        />
      </div>

      <div>
        <div className="label">Password</div>
        <input
          className="input"
          type="password"
          placeholder="Your password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
      </div>

      <div>
        <div className="label">Algorithm</div>
        <div className="algo-toggle">
          {[
            { key: "HS256", label: "HS256" },
            { key: "HS384", label: "HS384" },
            { key: "HS512", label: "HS512" },
            { key: "RS256", label: "RS256" },
            { key: "RS384", label: "RS384" },
            { key: "RS512", label: "RS512" },
          ].map((opt) => (
            <button
              key={opt.key}
              type="button"
              className={`algo-btn ${algo === opt.key ? "active" : ""}`}
              onClick={() => setAlgo(opt.key)}
            >
              {opt.label}
            </button>
          ))}
        </div>

        <div className="small-label" style={{ marginTop: 4 }}>
          Select signing algorithm for your JWT.
        </div>
      </div>

      <div>
        <div className="label">Expires In (seconds)</div>
        <input
          className="input"
          type="number"
          placeholder="3600"
          min={1}
          value={expiresIn}
          onChange={(e) => setExpiresIn(e.target.value)}
          required
        />
        <div className="small-label" style={{ marginTop: 4 }}>
          How long the access token should be valid (e.g., 3600 = 1 hour)
        </div>
      </div>

      <div className="switch-row">
        <div>
          <div className="label">Issue refresh token</div>
          <div className="small-label">
            Toggle to request a refresh token from the backend.
          </div>
        </div>
        <label className="switch">
          <input
            type="checkbox"
            checked={useRefresh}
            onChange={() => setUseRefresh((v) => !v)}
          />
          <span className="slider"></span>
        </label>
      </div>

      {error && <div className="error-text">{error}</div>}

      <button className="primary-btn" type="submit" disabled={loading}>
        {loading ? "Signing you in..." : "Log in"}
      </button>
    </form>
  );
}
