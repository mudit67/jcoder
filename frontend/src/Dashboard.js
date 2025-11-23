import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";

function getCookie(name) {
  if (typeof document === "undefined") return null;
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(";").shift();
  return null;
}

function base64UrlDecode(str) {
  try {
    let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
    const pad = base64.length % 4;
    if (pad === 2) base64 += "==";
    else if (pad === 3) base64 += "=";
    else if (pad === 1) base64 += "===";

    return atob(base64);
  } catch (e) {
    return null;
  }
}

export default function Dashboard() {
  const navigate = useNavigate();
  const [token, setToken] = useState(
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiIxMjM0NSIsIm5hbWUiOiJUZXN0IFVzZXIiLCJpYXQiOjE2OTk5OTk5OTl9.tf7WAe8ItNjqEea3Fsw5yJAkw1G8NxYn0G-4Av44CjE"
  );
  const [isLoading, setIsLoading] = useState(false);
  const [username, setUsername] = useState("");
  const [issuedAt, setIssuedAt] = useState("");
  useEffect(() => {
    let data = localStorage.getItem("data");
    if (data) {
      let result = JSON.parse(data)
      setUsername(result.username);
      setIssuedAt(new Date(result.issuedAt).toLocaleString());
    }
    let token = localStorage.getItem("accessToken");
    if (token) {
      setToken(token);
    }
  }, []);
  let header = null;
  let payload = null;
  let signature = null;
  let algo = null;

  if (token) {
    const parts = token.split(".");
    if (parts.length === 3) {
      const [h, p, s] = parts;
      signature = s;
      try {
        const hJson = base64UrlDecode(h);
        const pJson = base64UrlDecode(p);
        header = hJson ? JSON.parse(hJson) : null;
        payload = pJson ? JSON.parse(pJson) : null;
        algo = header?.alg || null;
      } catch (e) {
        console.log(e);
      }
    }
  }

  const handleBackToLogin = () => navigate("/login");

  const logout = () => {
    localStorage.removeItem("accessToken");
    navigate("/login", { replace: true });
  };

  const refreshToken = async () => {
    setIsLoading(true);
    try {
      const res = await fetch("http:localhost:3000/api/secret", {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      });

      if (!res.ok) throw new Error("Failed to refresh token");

      const result = await res.json();
      if (result?.data.secretMessage) {
        setToken(result?.data.secretMessage);
        localStorage.setItem("accessToken", result?.data.secretMessage);
      }
    } catch (error) {
      alert("Error refreshing token!");
      console.error(error);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="dashboard-card">
      <div className="dashboard-header">
        <div>
          <div className="auth-title">JWT Dashboard</div>
          <div className="auth-subtitle" onClick={logout}>
            Logout
          </div>
        </div>
        <div className="pill">
          {algo ? `Algorithm: ${algo}` : "No token loaded"}
        </div>
      </div>

      {token && (
  <div
    style={{
      display: "flex",
      justifyContent: "space-between",
      alignItems: "center",
      width: "100%",
      marginBottom: 12,
    }}
  >
    <button
      className="primary-btn"
      onClick={refreshToken}
      disabled={isLoading}
      style={{ width: "auto", marginRight: 12 }}
    >
      {isLoading ? "Refreshing..." : "🔄 Refresh Token"}
    </button>

    <div className="token-info">
      <div className="small-label" style={{ fontWeight: "500" }}>
        {username || "Unknown User"}
      </div>
      <div className="small-label" style={{ fontSize: "12px", opacity: 0.7 }}>
        {issuedAt ? `Issued: ${issuedAt}` : "IssuedAt not available"}
      </div>
    </div>
  </div>
)}


      {isLoading && (
        <div className="loading-spinner" style={{ marginBottom: 12 }} />
      )}

      {!token && (
        <div>
          <div className="error-text" style={{ marginBottom: 12 }}>
            No <code>accessToken</code> cookie found.
          </div>
          <button className="primary-btn" onClick={handleBackToLogin}>
            Go to Login
          </button>
        </div>
      )}

      {token && !isLoading && (
        <>
          <div className="small-label">Raw token</div>
          <div className="code-block" style={{ marginTop: 6 }}>
            {token}
          </div>

          <div className="columns">
            <div>
              <div className="code-title">Header</div>
              <div className="code-block">
                {header ? (
                  <pre>{JSON.stringify(header, null, 2)}</pre>
                ) : (
                  "Unable to decode header"
                )}
              </div>
            </div>
            <div>
              <div className="code-title">Payload</div>
              <div className="code-block">
                {payload ? (
                  <pre>{JSON.stringify(payload, null, 2)}</pre>
                ) : (
                  "Unable to decode payload"
                )}
              </div>
            </div>
          </div>

          <div style={{ marginTop: 16 }}>
            <div className="code-title">Signature (base64url)</div>
            <div className="code-block">
              {signature || "No signature part found"}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
