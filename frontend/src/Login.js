import React, { useState } from "react";
import { useNavigate } from "react-router-dom";

function setCookie(name, value, days = 30) {
  const expires = new Date();
  expires.setTime(expires.getTime() + (days * 24 * 60 * 60 * 1000));
  document.cookie = `${name}=${value}; expires=${expires.toUTCString()}; path=/; SameSite=Strict; Secure=${window.location.protocol === 'https:'}`;
}

export default function Login() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [algo, setAlgo] = useState("HS256"); // Default to HS256
  const [useRefresh, setUseRefresh] = useState(false);
  const [expiresIn, setExpiresIn] = useState("1h"); // Use time format instead of seconds
  const [customExpiration, setCustomExpiration] = useState("");
  const [useCustomExpiration, setUseCustomExpiration] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const res = await fetch("http://localhost:3000/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username,
          password,
          algorithm: algo,
          expiresIn: useCustomExpiration ? customExpiration : expiresIn,
          issueRefreshToken: useRefresh,
        }),
      });

      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.message || "Login failed");
      }
      const result = await res.json();
      localStorage.setItem("accessToken", result.data.accessToken);
      localStorage.setItem("data", JSON.stringify({
        "username": result.data.user.username, 
        "issuedAt": result.data.issuedAt,
        "expiresAt": result.data.expiresAt,
        "originalExpiresIn": useCustomExpiration ? customExpiration : expiresIn
      }));
      
      // Store refresh token in HTTP cookie if provided
      if (result.data.refreshToken) {
        setCookie("refreshToken", result.data.refreshToken, 30);
      }

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
          Select signing algorithm.
        </div>
      </div>

      <div>
        <div className="label">Expires In</div>
        <div className="algo-toggle" style={{ marginBottom: "12px", gridTemplateColumns: "1fr 1fr" }}>
          <button
            type="button"
            className={`algo-btn ${!useCustomExpiration ? "active" : ""}`}
            onClick={() => setUseCustomExpiration(false)}
          >
            Preset
          </button>
          <button
            type="button"
            className={`algo-btn ${useCustomExpiration ? "active" : ""}`}
            onClick={() => setUseCustomExpiration(true)}
          >
            Custom
          </button>
        </div>
        
        {!useCustomExpiration ? (
          <select 
            className="input"
            value={expiresIn}
            onChange={(e) => setExpiresIn(e.target.value)}
            required
          >
            <option value="5">5 seconds</option>
            <option value="10">10 seconds</option>
            <option value="15m">15 minutes</option>
            <option value="1h">1 hour</option>
            <option value="24h">24 hours</option>
            <option value="7d">7 days</option>
            <option value="30d">30 days</option>
          </select>
        ) : (
          <input
            className="input"
            type="number"
            placeholder="3600 (1 hour)"
            min="1"
            value={customExpiration}
            onChange={(e) => setCustomExpiration(e.target.value)}
            required
          />
        )}
        
        <div className="small-label" style={{ marginTop: 4 }}>
          {useCustomExpiration 
            ? "Enter expiration time in seconds (e.g., 3600 = 1 hour)"
            : "Select how long the access token should be valid"
          }
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
